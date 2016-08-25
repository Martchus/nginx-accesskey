/*
 * nginx (c) Igor Sysoev
 * this module (C) Mykola Grechukh <gns@altlinux.org>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#define NGX_ACCESSKEY_MD5 1
#define NGX_ACCESSKEY_SHA1 2

typedef struct {
    ngx_flag_t    enable;
    ngx_str_t     arg;
    ngx_uint_t    hashmethod;
    ngx_str_t     signature;
    ngx_array_t  *signature_lengths;
    ngx_array_t  *signature_values;
} ngx_http_accesskey_loc_conf_t;

static ngx_int_t ngx_http_accesskey_handler(ngx_http_request_t *r);

static char *ngx_http_accesskey_signature(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_accesskey_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_accesskey_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_accesskey_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_accesskey_init(ngx_conf_t *cf);

static ngx_conf_post_handler_pt  ngx_http_accesskey_signature_p =
    ngx_http_accesskey_signature;

static ngx_command_t  ngx_http_accesskey_commands[] = {
    { ngx_string("accesskey"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_accesskey_loc_conf_t, enable),
      NULL },

    { ngx_string("accesskey_hashmethod"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_accesskey_hashmethod,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("accesskey_signature"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_accesskey_loc_conf_t, signature),
      &ngx_http_accesskey_signature_p },

    { ngx_string("accesskey_arg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_accesskey_loc_conf_t, arg),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_accesskey_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_accesskey_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_accesskey_create_loc_conf,       /* create location configuration */
    ngx_http_accesskey_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_accesskey_module = {
    NGX_MODULE_V1,
    &ngx_http_accesskey_module_ctx,           /* module context */
    ngx_http_accesskey_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_accesskey_handler(ngx_http_request_t *r)
{
    ngx_uint_t   i;
    ngx_uint_t   hashlength,bhashlength;
    ngx_http_accesskey_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_accesskey_module);

    if (!alcf->enable) {
        return NGX_OK;
    }

    if (!alcf->signature_lengths || !alcf->signature_values) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "accesskey enabled, but signature not configured!");
        return NGX_HTTP_FORBIDDEN;
    }

    switch(alcf->hashmethod) {
        case NGX_ACCESSKEY_SHA1:
            bhashlength=20; break;

	case NGX_ACCESSKEY_MD5:
            bhashlength=16; break;

        default: 
           ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
               "accesskey: hash not supported");
           return NGX_HTTP_FORBIDDEN;
    }
    hashlength=bhashlength*2;

    ngx_str_t args = r->args;
    ngx_str_t look = alcf->arg;

    ngx_uint_t j=0,k=0,l=0;

    for (i = 0; i <= args.len; i++) {
        if ( ( i == args.len) || (args.data[i] == '&') ) {
            if (j > 1) { k = j; l = i; }
            j = 0;
        } else if ( (j == 0) && (i<args.len-look.len) ) {
            if ( (ngx_strncmp(args.data+i, look.data, look.len) == 0)
                    && (args.data[i+look.len] == '=') ) {
                j=i+look.len+1;
                i=j-1;
            } else j=1;
        }
    }

    if (l-k!=hashlength) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "accesskey: length %d of \"%V\" argument is not equal %d",
            l-k, &look, hashlength);
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_str_t val;
    if (ngx_http_script_run(r, &val, alcf->signature_lengths->elts, 0, alcf->signature_values->elts) == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "accesskey: evaluation failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "accesskey: evaluated value of signature: \"%V\"", &val);

    u_char hashb[64], hasht[128];

    MD5_CTX md5;
    SHA_CTX sha;

    switch(alcf->hashmethod) {
	case NGX_ACCESSKEY_MD5: 
            MD5Init(&md5);
            MD5Update(&md5,val.data,val.len);
            MD5Final(hashb, &md5);
            break;
        case NGX_ACCESSKEY_SHA1: 
            SHA1_Init(&sha);
            SHA1_Update(&sha,val.data,val.len);
            SHA1_Final(hashb,&sha);
            break;
    };

    static u_char hex[] = "0123456789abcdef";
    u_char *text = hasht;

    for (i = 0; i < bhashlength; i++) {
        *text++ = hex[hashb[i] >> 4];
        *text++ = hex[hashb[i] & 0xf];
    }

    *text = '\0';

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "accesskey: hash value \"%s\"", hasht);

    if (ngx_strncmp(hasht,args.data+k,hashlength)!=0)
            return NGX_HTTP_FORBIDDEN;

    return NGX_OK;
}

static char *
ngx_http_accesskey_compile_signature(ngx_conf_t *cf, ngx_http_accesskey_loc_conf_t *alcf)
{

    ngx_http_script_compile_t   sc;
    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &alcf->signature;
    sc.lengths = &alcf->signature_lengths;
    sc.values = &alcf->signature_values;
    sc.variables = ngx_http_script_variables_count(&alcf->signature);;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_accesskey_signature(ngx_conf_t *cf, void *post, void *data)
{
    ngx_http_accesskey_loc_conf_t *alcf =
	    ngx_http_conf_get_module_loc_conf(cf, ngx_http_accesskey_module);

    return ngx_http_accesskey_compile_signature(cf, alcf);
}

static char *
ngx_http_accesskey_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *d = cf->args->elts;
    ngx_http_accesskey_loc_conf_t *alcf = conf;

    if ( (d[1].len == 3 ) && (ngx_strncmp(d[1].data,"md5",3) == 0) ) {
        alcf->hashmethod = NGX_ACCESSKEY_MD5;
    } else if ( (d[1].len == 4) && (ngx_strncmp(d[1].data,"sha1",4) == 0) ){
        alcf->hashmethod = NGX_ACCESSKEY_SHA1;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "accesskey_hashmethod should be md5 or sha1, not \"%V\"", d+1);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_accesskey_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_accesskey_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_accesskey_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_accesskey_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_accesskey_loc_conf_t  *prev = parent;
    ngx_http_accesskey_loc_conf_t  *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->hashmethod, prev->hashmethod, NGX_ACCESSKEY_MD5);
    ngx_conf_merge_str_value(conf->arg, prev->arg, "key");
    ngx_conf_merge_str_value(conf->signature,prev->signature,"$remote_addr");
    return ngx_http_accesskey_compile_signature(cf, conf);
}


static ngx_int_t
ngx_http_accesskey_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_accesskey_handler;

    return NGX_OK;
}
