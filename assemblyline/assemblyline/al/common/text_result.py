SRV_DOWN_HASH = "eb54dc2e040a925f84e55e91ff27601ad"
MAX_RETRY_HASH = "ec502020e499f01f230e06a58ad9b5dcc"
MAX_DEPTH_HASH = "e56d398ad9e9c4de4dd0ea8897073d430"
MAX_FILES_HASH = "e6e34a5b7aa6fbfb6b1ac0d35f2c44d70"

KNOWN_ERRORS = {
    SRV_DOWN_HASH: "SERVICE_DOWN",
    MAX_RETRY_HASH: "MAX_RETRY_REACHED",
    MAX_DEPTH_HASH: "MAX_EMBEDDED_DEPTH_REACHED",
    MAX_FILES_HASH: "MAX_FILES_REACHED",
}

def al_result_to_text(r, show_errors=True, verbose_error=False):
    lines = [""]
    lines.append(":: Submission Detail %s::" % {True: "", False: "[Errors hidden]"}[show_errors] )
    lines.append("\t%-20s %s" % ("state:", r["state"]))
    lines.append("")
    for key in sorted(r['submission'].keys()):
        if type(r['submission'][key]) == type([]):
            lines.append("\t%-20s %s" % (key+":", " | ".join(r['submission'][key])))
        else:
            lines.append("\t%-20s %s" % (key+":", r['submission'][key]))
    lines.append("")
    lines.append("\t:: Timing info ::")
    for key in sorted(r['times'].keys()):
        lines.append("\t\t%-12s %s" % (key+":", r['times'][key].replace("T", " ").replace("Z", "")))
    lines.append("\t\t%-12s %s" % ("expiry:", r["__expiry_ts__"].replace("T", " ").replace("Z", "")))
    lines.append("")
    lines.append("\t:: Services info ::")
    for key in sorted(r['services'].keys()):
        if type(r['services'][key]) == type([]):
            lines.append("\t\t%-12s %s" % (key+":", " | ".join(r['services'][key])))
        else:
            lines.append("\t\t%-12s %s" % (key+":", r['services'][key]))
    
    lines.append("")
    lines.append("\t:: Missing results/errors ::")
    if len(r['missing_result_keys']) == 0 and len(r['missing_error_keys']) == 0:
        lines.append("\t\tNone")
    else:
        for i in r['missing_result_keys']:
            lines.append("\t\t%s [RESULT]" % i)
        for i in r['missing_error_keys']:
            lines.append("\t\t%s [ERROR]" % i)
    
    lines.append("")
    lines.append(":: Submitted files ::")
    for name, sha256 in r['files']:
        lines.append("\t%s [%s]" % (name, sha256))
    
    if show_errors and len(r['errors']) > 0:
        lines.append("")
        lines.append(":: ERRORS ::")
        for key in r['errors'].keys():
            sha256 = key[:64]
            service = key[65:].split(".", 1)[0]
            ehash = key[-33:]
            if ehash in KNOWN_ERRORS:
                lines.append("\tService %s failed for file %s [%s]" % (service, sha256, KNOWN_ERRORS[ehash]))
            else:
                lines.append("\tService %s failed for file %s [%s]" % (service, sha256, r['errors'][key]["response"]['status']))
                if verbose_error and r['errors'][key]["response"]["message"] != "": 
                    err_lines = r['errors'][key]["response"]["message"].split("\n")
                    for l in err_lines:
                        lines.append("\t\t%s" % l)
        
    lines.append("")
    lines.append(":: Service results ::")
    res_key_list = sorted(r['results'].keys())
    for _, sha256 in r['files']:
        for key in res_key_list:
            if key.startswith(sha256):
                lines.extend(process_res(r['results'][key], sha256))        
                del r['results'][key]
    
    for key in sorted(r['results'].keys()):
        lines.extend(process_res(r['results'][key], key[:64]))
        
    return lines

def process_res(res, sha256):
    out = [""]
    out.extend(get_service_info(res, sha256))
    out.extend(recurse_sections(res['result']['sections']))
    
    if res['result']['tags']:
        out.append('')
        out.append("\t\t:: Generated Tags ::")
        for tag in res['result']['tags']:
            out.append("\t\t\t%s [%s]" % (tag['value'], tag['type']))
        
    
    if res['response']['extracted']:
        out.append('')
        out.append("\t\t:: Extracted files ::")
        for extracted in res['response']['extracted']:
            name, fhash = extracted[:2]
            out.append("\t\t\t%s [%s]" % (name, fhash))
    
    return out

def get_service_info(srv_res, fhash):
    out=[]
    out.append("\t:: %s [%s] - %s (%s) ::" %(srv_res['response']['service_name'], srv_res['result']['score'], srv_res['response']['service_version'], fhash))
    return out

def recurse_sections(sections, depth=1):
    out = []
    first = True
    for section in sections:
        if not first:
            out.append("")
        out.append("\t%s[%s] %s" % ("\t"*depth, section['score'], section['title_text'].replace("\n", "")))
        
        if section['body']:
            out.extend(["\t\t%s%s" % ("\t"*depth, x) for x in section['body'].splitlines()])
        
        if section['subsections']:
            out.extend(recurse_sections(section['subsections'], depth+1))
        
        first = False
        
    return out
