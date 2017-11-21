
#include "mod_security3.h"
#include "msc_config.h"
#include "msc_filters.h"


#ifndef OLD_MSC_CONFIG_STYLE
    /* -- Configuration directives definitions -- */

#define CMD_SCOPE_MAIN  (RSRC_CONF)
#define CMD_SCOPE_ANY   (RSRC_CONF | ACCESS_CONF)

#if defined(HTACCESS_CONFIG)
#define CMD_SCOPE_HTACCESS  (OR_OPTIONS)
#endif
#endif

const command_rec module_directives[] =
{
    AP_INIT_TAKE1(
        "modsecurity",
        msc_config_modsec_state,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "The argument must be either 'On' or 'Off'"
    ),

    AP_INIT_TAKE1(
        "modsecurity_rules",
        msc_config_load_rules,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Please ensure that the arugment is specified correctly, including line continuations."
    ),

    AP_INIT_TAKE1(
        "modsecurity_rules_file",
        msc_config_load_rules_file,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Load ModSecurity rules from a file"
    ),

    AP_INIT_TAKE2(
        "modsecurity_rules_remote",
        msc_config_load_rules_remote,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Load ModSecurity rules from a remote server"
    ),


#ifndef OLD_MSC_CONFIG_STYLE
#ifdef HTACCESS_CONFIG
    AP_INIT_TAKE1 (
        "SecAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_HTACCESS,
        "an action list"
    ),
#else
    AP_INIT_TAKE1 (
        "SecAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "an action list"
    ),
#endif

    AP_INIT_TAKE1 (
        "SecArgumentSeparator",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "character that will be used as separator when parsing application/x-www-form-urlencoded content."
    ),

    AP_INIT_TAKE1 (
        "SecCookiev0Separator",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "character that will be used as separator when parsing cookie v0 content."
    ),

    AP_INIT_TAKE1 (
        "SecAuditEngine",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On, Off or RelevantOnly to determine the level of audit logging"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLog",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "filename of the primary audit log file"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLog2",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "filename of the secondary audit log file"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLogParts",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "list of audit log parts that go into the log."
    ),

    AP_INIT_TAKE1 (
        "SecAuditLogRelevantStatus",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "regular expression that will be used to determine if the response status is relevant for audit logging"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLogType",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "whether to use the old audit log format (Serial) or new (Concurrent)"
    ),

#ifdef WITH_YAJL
    AP_INIT_TAKE1 (
        "SecAuditLogFormat",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "whether to emit audit log data in native format or JSON"
    ),
#endif

    AP_INIT_TAKE1 (
        "SecAuditLogStorageDir",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "path to the audit log storage area; absolute, or relative to the root of the server"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLogDirMode",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "octal permissions mode for concurrent audit log directories"
    ),

    AP_INIT_TAKE1 (
        "SecAuditLogFileMode",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "octal permissions mode for concurrent audit log files"
    ),

    AP_INIT_TAKE12 (
        "SecCacheTransformations",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "whether or not to cache transformations. Defaults to true."
    ),

    AP_INIT_TAKE1 (
        "SecChrootDir",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "path of the directory to which server will be chrooted"
    ),

    AP_INIT_TAKE1 (
        "SecComponentSignature",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "component signature to add to ModSecurity signature."
    ),

    AP_INIT_FLAG (
        "SecContentInjection",
        cmd_msc_flag,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_FLAG (
        "SecStreamOutBodyInspection",
        cmd_msc_flag,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_FLAG (
        "SecStreamInBodyInspection",
        cmd_msc_flag,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecCookieFormat",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "version of the Cookie specification to use for parsing. Possible values are 0 and 1."
    ),

    AP_INIT_TAKE1 (
        "SecDataDir",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "path to the persistent data storage area" // TODO
    ),

    AP_INIT_TAKE1 (
        "SecDebugLog",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "path to the debug log file"
    ),

    AP_INIT_TAKE1 (
        "SecDebugLogLevel",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "debug log level, which controls the verbosity of logging."
        " Use values from 0 (no logging) to 9 (a *lot* of logging)."
    ),

    AP_INIT_TAKE1 (
        "SecCollectionTimeout",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "set default collections timeout. default it 3600"
    ),

    AP_INIT_TAKE1 (
        "SecDefaultAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "default action list"
    ),

    AP_INIT_FLAG (
        "SecDisableBackendCompression",
        cmd_msc_flag,
        NULL,
        CMD_SCOPE_ANY,
        "When set to On, removes the compression headers from the backend requests."
    ),

    AP_INIT_TAKE1 (
        "SecGsbLookupDB",
        cmd_msc_take1,
        NULL,
        RSRC_CONF,
        "database google safe browsing"
    ),

    AP_INIT_TAKE1 (
        "SecUnicodeCodePage",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "Unicode CodePage"
    ),

    AP_INIT_TAKE12 (
        "SecUnicodeMapFile",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_MAIN,
        "Unicode Map file"
    ),

    AP_INIT_TAKE1 (
        "SecGeoLookupDB",
        cmd_msc_take1,
        NULL,
        RSRC_CONF,
        "database for geographical lookups module."
    ),

    AP_INIT_TAKE12 (
        "SecGuardianLog",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_MAIN,
        "The filename of the filter debugging log file"
    ),

    AP_INIT_TAKE1 (
        "SecMarker",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "marker for a skipAfter target"
    ),

    AP_INIT_TAKE1 (
        "SecPcreMatchLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "PCRE match limit"
    ),

    AP_INIT_TAKE1 (
        "SecPcreMatchLimitRecursion",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "PCRE match limit recursion"
    ),

    AP_INIT_TAKE1 (
        "SecRequestBodyAccess",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecInterceptOnError",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecRulePerfTime",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "Threshold to log slow rules in usecs."
    ),

    AP_INIT_TAKE12 (
        "SecConnReadStateLimit",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "maximum number of threads in READ_BUSY state per ip address"
    ),

    AP_INIT_TAKE12 (
        "SecReadStateLimit",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "maximum number of threads in READ_BUSY state per ip address"
    ),

    AP_INIT_TAKE12 (
        "SecConnWriteStateLimit",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "maximum number of threads in WRITE_BUSY state per ip address"
    ),

    AP_INIT_TAKE12 (
        "SecWriteStateLimit",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "maximum number of threads in WRITE_BUSY state per ip address"
    ),

    AP_INIT_TAKE1 (
        "SecRequestBodyInMemoryLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "maximum request body size that will be placed in memory (except for POST urlencoded requests)."
    ),

    AP_INIT_TAKE1 (
        "SecRequestBodyLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "maximum request body size ModSecurity will accept."
    ),

    AP_INIT_TAKE1 (
        "SecRequestBodyNoFilesLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "maximum request body size ModSecurity will accept, but excluding the size of uploaded files."
    ),

    AP_INIT_TAKE1 (
        "SecRequestEncoding",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "character encoding used in request."
    ),

    AP_INIT_TAKE1 (
        "SecResponseBodyAccess",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecResponseBodyLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "byte limit for response body"
    ),

    AP_INIT_TAKE1 (
        "SecResponseBodyLimitAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "what happens when the response body limit is reached"
    ),

    AP_INIT_TAKE1 (
        "SecRequestBodyLimitAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "what happens when the request body limit is reached"
    ),

    AP_INIT_ITERATE (
        "SecResponseBodyMimeType",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_ANY,
        "adds given MIME types to the list of types that will be buffered on output"
    ),

    AP_INIT_NO_ARGS (
        "SecResponseBodyMimeTypesClear",
        cmd_msc_no_args,
        NULL,
        CMD_SCOPE_ANY,
        "clears the list of MIME types that will be buffered on output"
    ),

#ifdef HTACCESS_CONFIG
    AP_INIT_TAKE23 (
        "SecRule",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule target, operator and optional action list"
    ),
#else
    AP_INIT_TAKE23 (
        "SecRule",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_ANY,
        "rule target, operator and optional action list"
    ),
#endif

    AP_INIT_TAKE1 (
        "SecRuleEngine",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecStatusEngine",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecConnEngine",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE23 (
        "SecRemoteRules",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_ANY,
        "key and URI to the remote rules"
    ),

    AP_INIT_TAKE1 (
        "SecRemoteRulesFailAction",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "Abort or Warn"
    ),


    AP_INIT_TAKE1 (
        "SecXmlExternalEntity",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_FLAG (
        "SecRuleInheritance",
        cmd_msc_flag,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE12 (
        "SecRuleScript",
        cmd_msc_take12,
        NULL,
        CMD_SCOPE_ANY,
        "rule script and optional actionlist"
    ),

#ifdef HTACCESS_CONFIG
    AP_INIT_ITERATE (
        "SecRuleRemoveById",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule ID for removal"
    ),

    AP_INIT_ITERATE (
        "SecRuleRemoveByTag",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule tag for removal"
    ),

    AP_INIT_ITERATE (
        "SecRuleRemoveByMsg",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule message for removal"
    ),
#else
    AP_INIT_ITERATE (
        "SecRuleRemoveById",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_ANY,
        "rule ID for removal"
    ),

    AP_INIT_ITERATE (
        "SecRuleRemoveByTag",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_ANY,
        "rule tag for removal"
    ),

    AP_INIT_ITERATE (
        "SecRuleRemoveByMsg",
        cmd_msc_iterate,
        NULL,
        CMD_SCOPE_ANY,
        "rule message for removal"
    ),
#endif

    AP_INIT_TAKE2 (
        "SecHashMethodPm",
        cmd_msc_take2,
        NULL,
        CMD_SCOPE_ANY,
        "Hash method and pattern"
    ),

    AP_INIT_TAKE2 (
        "SecHashMethodRx",
        cmd_msc_take2,
        NULL,
        CMD_SCOPE_ANY,
        "Hash method and regex"
    ),

#ifdef HTACCESS_CONFIG
    AP_INIT_TAKE2 (
        "SecRuleUpdateActionById",
        cmd_msc_take2,
        NULL,
        CMD_SCOPE_HTACCESS,
        "updated action list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetById",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_HTACCESS,
        "updated target list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetByTag",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule tag pattern and updated target list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetByMsg",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_HTACCESS,
        "rule message pattern and updated target list"
    ),
#else
    AP_INIT_TAKE2 (
        "SecRuleUpdateActionById",
        cmd_msc_take2,
        NULL,
        CMD_SCOPE_ANY,
        "updated action list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetById",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_ANY,
        "updated target list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetByTag",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_ANY,
        "rule tag pattern and updated target list"
    ),

    AP_INIT_TAKE23 (
        "SecRuleUpdateTargetByMsg",
        cmd_msc_take23,
        NULL,
        CMD_SCOPE_ANY,
        "rule message pattern and updated target list"
    ),
#endif

    AP_INIT_TAKE1 (
        "SecServerSignature",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "the new signature of the server"
    ),

    AP_INIT_TAKE1 (
        "SecTmpDir",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "path to the temporary storage area"
    ),

    AP_INIT_TAKE1 (
        "SecUploadDir",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "path to the file upload area"
    ),

    AP_INIT_TAKE1 (
        "SecUploadFileLimit",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "limit the number of uploaded files processed"
    ),

    AP_INIT_TAKE1 (
        "SecUploadFileMode",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "octal permissions mode for uploaded files"
    ),

    AP_INIT_TAKE1 (
        "SecUploadKeepFiles",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecTmpSaveUploadedFiles",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE1 (
        "SecWebAppId",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "id"
    ),

    AP_INIT_TAKE1 (
        "SecSensorId",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_MAIN,
        "sensor id"
    ),

    AP_INIT_TAKE1 (
        "SecHttpBlKey",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "httpBl access key"
    ),

    AP_INIT_TAKE1 (
        "SecHashEngine",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "On or Off"
    ),

    AP_INIT_TAKE2 (
        "SecHashKey",
        cmd_msc_take2,
        NULL,
        CMD_SCOPE_ANY,
        "Set Hash key"
    ),

    AP_INIT_TAKE1 (
        "SecHashParam",
        cmd_msc_take1,
        NULL,
        CMD_SCOPE_ANY,
        "Set Hash parameter"
    ),

#endif

    {NULL}
};


static const char *msc_config_modsec_state(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;

    if (strcasecmp(p1, "On") == 0)
    {
        cnf->msc_state = 1;
    }
    else if (strcasecmp(p1, "Off") == 0)
    {
        cnf->msc_state = 0;
    }
    else
    {
        return "ModSecurity state must be either 'On' or 'Off'";
    }

    return NULL;
}


static const char *msc_config_load_rules(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add(cnf->rules_set, p1, &error);

    if (ret < 0)
    {
        return error;
    }

    return NULL;
}


static const char *msc_config_load_rules_file(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add_file(cnf->rules_set, p1, &error);

    if (ret < 0)
    {
        return error;
    }

    return NULL;
}


static const char *msc_config_load_rules_remote(cmd_parms *cmd, void *_cnf,
    const char *p1, const char *p2)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add_remote(cnf->rules_set, p1, p2, &error);

    if (ret < 0)
    {
        return error;
    }

    return NULL;
}

void *msc_hook_create_config_directory(apr_pool_t *mp, char *path)
{
    msc_conf_t *cnf = NULL;

    cnf = apr_pcalloc(mp, sizeof(msc_conf_t));
    if (cnf == NULL)
    {
        goto end;
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Created directory config for path: %s [%pp]", path, cnf);
#endif

    cnf->rules_set = msc_create_rules_set();
    if (path != NULL)
    {
        cnf->name_for_debug = strdup(path);
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Config for path: %s is at: %pp", path, cnf);
#endif

end:
    return cnf;
}


void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child)
{
    msc_conf_t *cnf_p = parent;
    msc_conf_t *cnf_c = child;
    msc_conf_t *cnf_new = (msc_conf_t *)msc_hook_create_config_directory(mp, cnf_c->name_for_debug);

    if (cnf_p && cnf_c)
    {
        const char *error = NULL;
        int ret;
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child %pp [%s]" \
            "into: %pp", cnf_p,
            cnf_p->name_for_debug,
            child, cnf_c->name_for_debug, cnf_new);
#endif
        cnf_new->name_for_debug = cnf_c->name_for_debug;

        ret = msc_rules_merge(cnf_new->rules_set, cnf_c->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }

        ret = msc_rules_merge(cnf_new->rules_set, cnf_p->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge OK");
#endif
    }
    else if (cnf_c && !cnf_p)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent -NULL- [-NULL-] child %pp [%s]",
            cnf_c, cnf_c->name_for_debug);
#endif
    }
    else if (cnf_p && !cnf_c)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child -NULL- [-NULL-]",
            cnf_p, cnf_p->name_for_debug);
#endif
    }

    return cnf_new;
}


static const char *cmd_msc_take1(cmd_parms *cmd, void *_dcfg, const char *p1) {
    printf("%s %s\n", cmd->cmd->name, p1);
    return NULL;
}


static const char *cmd_msc_take12(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2) {
    printf("%s \"%s\" \"%s\"\n", cmd->cmd->name, p1, p2);
    return NULL;
}


static const char *cmd_msc_take2(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2) {
    printf("%s \"%s\" \"%s\"\n", cmd->cmd->name, p1, p2);
    return NULL;
}


static const char *cmd_msc_take23(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2, const char *p3) {
    printf("%s \"%s\" \"%s\" \"%s\"\n", cmd->cmd->name, p1, p2, p3);
    return NULL;
}


static const char *cmd_msc_flag(cmd_parms *cmd, void *_dcfg, int flag) {
    printf("%s %d\n", cmd->cmd->name, flag);
    return NULL;
}


static const char *cmd_msc_iterate(cmd_parms *cmd, void *_dcfg,
    const char *_p1) {
    printf("%s \"%s\"\n", cmd->cmd->name, _p1);
    return NULL;
}


static const char *cmd_msc_no_args(cmd_parms *cmd, void *_dcfg) {
    printf("%s\n", cmd->cmd->name);
    return NULL;
}

