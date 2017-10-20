from assemblyline.al.common import forge
import yara
import traceback


if __name__ == "__main__":
    """ yara_dbg - Figure out which rule is throwing shade 
    
    Run from somewhere with access to the datastore.
    
    This script will download the last 100 files to throw YARA errors,
    and print out the exact rule name that caused the error.
    
    TODO:
     - Rule dependencies
     - Port to assemblyline_client
    
    """
    DS = forge.get_datastore()
    YP = forge.get_yara_parser()

    Error_list = DS.list_errors("response.service_name:Yara", start=0, rows=100)

    sig_keys = DS.list_filtered_signature_keys("meta.al_status:DEPLOYED OR meta.al_status:NOISY")
    signature_list = DS.get_signatures(sig_keys)

    rule_set = []
    for s in signature_list:
        rule_val = YP().dump_rule_file([s])
        try:
            rule_set.append((s['name'], yara.compile(source=rule_val)))
        except KeyboardInterrupt:
            raise
        except:
            traceback.print_exc()
            print rule_val

    for item in Error_list.get("items", []):
        srl = item.get("srl")
        if srl is not None:
            with forge.get_filestore() as f_transport:
                data = f_transport.get(srl)

            if data is None:
                continue
            for name, rule in rule_set:
                try:
                    rule.match(data=data)
                except KeyboardInterrupt:
                    raise
                except yara.Error as e:
                    print "Error in", name, e.message


