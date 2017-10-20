def make_vm_dict(name, ram_gb, vcpus, revert_every, virtual_disk_url,
                 os_type, os_variant, num_workers=1):  # pylint: disable=R0913
    return {
        'num_workers': num_workers,
        'cfg': {
            'enabled': True,
            'name': name,
            'os_type': os_type,
            'os_variant': os_variant,
            'ram': ram_gb,
            'revert_every': revert_every,
            'vcpus': vcpus,
            'virtual_disk_url': virtual_disk_url,
        }
    }


DEFAULT_SEED = {
    'auth': {
        'allow_2fa': True,
        'allow_apikeys': True,
        'allow_u2f': True,
        'apikey_handler': 'al_ui.site_specific.validate_apikey',
        'dn_handler': 'al_ui.site_specific.validate_dn',
        'encrypted_login': True,
        'internal': {
            'enabled': True,
            'failure_ttl': 60,
            'max_failures': 5,
            'strict_requirements': True,
            'users': {
                'admin': {
                    'uname': 'admin',
                    'name': 'Default admin user',
                    'password': 'changme',
                    'groups': ['ADMIN', 'INTERNAL', 'USERS'],
                    'is_admin': True,
                    'classification': 'UNRESTRICTED'
                },
                'internal': {
                    'uname': 'internal',
                    'name': 'Internal re-submission user',
                    'password': 'Int3rn@lP4s$',
                    'groups': ['INTERNAL'],
                    'is_admin': False,
                    'classification': 'UNRESTRICTED'
                }
            },
        },
        'userpass_handler': 'al_ui.site_specific.validate_userpass'
    },

    'core': {
        'nodes': ['localhost'],
        'alert_actions': {
            'worker_count': 16,
            'tasker_count': 4
        },
        'alerter': {
            'create_alert': 'assemblyline.al.common.alerting.create_alert',
            "constant_alert_fields": ["event_id", "filename", "md5", "sha1", "sha256", "size", "ts"],
            "default_group_field": "md5",
            "filtering_group_fields": ["filename", "status"],
            'metadata_fields': {},
            'metadata_aliases': {},
            "non_filtering_group_fields": ["md5", "sha1", "sha256"],
            'shards': 2
        },
        'dispatcher': {
            'max': {
                'depth': 5,
                'files': 512,
                'inflight': 1000,
                'retries': 1,
            },
            'shards': 2,
            'timeouts': {
                'child': 60,
                'watch_queue': 86400,
            }
        },
        'expiry': {
            'journal': {
                'directory': '/opt/al/var/expiry',
                'ttl': 15,
            },
            'workers': 10,
            'delete_storage': True
        },
        "metricsd": {
            "extra_metrics": {}
        },
        'middleman': {
            'classification': 'UNRESTRICTED',
            'default_prefix': 'Bulk',
            'dropper_threads': 2,
            'expire_after': 15 * 24 * 60 * 60,
            'incomplete_expire_after': 60 * 60,
            'incomplete_stale_after': 30 * 60,
            'ingester_threads': 8,
            'max_extracted': 100,
            'max_supplementary': 100,
            'max_value_size': 4096,
            'sampling_at': {
                'low':    10000000,
                'medium':  2000000,
                'high':    1000000,
                'critical': 500000
            },
            'shards': 2,
            'stale_after': 1 * 24 * 60 * 60,
            'submitter_threads': 4,
            'user': 'internal',
        },
        'redis': {
            'nonpersistent': {
                'db': 6,
                'host': 'localhost',
                'port': 6379,
            },
            'persistent': {
                'db': 5,
                'host': 'localhost',
                'port': 6380,
            },
        },
        'bulk': {
            'compute_notice_field': 'assemblyline.common.null.compute_notice_field',
            'get_whitelist_verdict': 'assemblyline.al.common.signaturing.drop',
            'is_low_priority': 'assemblyline.common.null.is_low_priority',
            'whitelist': 'assemblyline.common.null.whitelist',
        },

    },

    'datasources': {
        'AL': {
            'classpath': 'assemblyline.al.datasource.al.AL',
            'config': {}
        },
        'Alert': {
            'classpath': 'assemblyline.al.datasource.alert.Alert',
            'config': {}
        },
        'Beaver': {
            'classpath': 'al_services.alsvc_beaver.datasource.beaver.Beaver',
            'config': 'services.master_list.Beaver.config'
        },
        'CFMD': {
            'classpath': 'al_services.alsvc_cfmd.datasource.cfmd.CFMD',
            'config': 'services.master_list.CFMD.config'
        },
        'NSRL': {
            'classpath': 'al_services.alsvc_nsrl.datasource.nsrl.NSRL',
            'config': 'services.master_list.NSRL.config'
        }
    },

    'datastore': {
        'hosts': ['datastore.al'],  # datastore.al is patch during installation to resolv to localhost
        'port': 8087,
        'solr_port': 8093,
        'stream_port': 8098,
        'default_timeout': 60,
        'riak': {
            'nodes': ['localhost'],
            'ring_size': 128,
            'nvals': {
                'low': 1,
                'med': 2,
                'high': 3
            },
            'solr': {
                'heap_min_gb': 1,
                'heap_max_gb': 4,
                'gc': '-XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=80',
            },
            'tweaks': {
                '10gnic': False,
                'disableswap': True,
                'jetty': False,
                'fs': True,
                'net': True,
                'noop_scheduler': True,
                'tuned_solr_configs': True,
            },
        },
    },

    'filestore': {
        'ftp_password': 'Ch@ang3thisPassword',  # The FTP user password
        'ftp_root': '/opt/al/var',
        'ftp_user': 'alftp',
        'ftp_ip_restriction': None,
        'support_urls': ['ftp://alftp:Ch@ang3thisPassword@localhost/opt/al/var/support'],
        'urls': ['ftp://alftp:Ch@ang3thisPassword@localhost/opt/al/var/storage'],
    },

    'installation': {
        'docker': {
            'apt_repo_info': 'deb https://apt.dockerproject.org/repo ubuntu-trusty main',
            'apt_repo_key_url': 'https://apt.dockerproject.org/gpg',
            'private_registry': 'localhost:5000'
        },
        'hooks': {
            'ui_pre': [],
            'riak_pre': [],
            'core_pre': [],
        },
        'external_packages': {
            'assemblyline': {
                'transport': 's3',
                'args': {
                    'base': '/opt/al/var/support',
                    'accesskey': 'AKIAIIESFCKMSXUP6KWQ',
                    'secretkey': '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',
                    's3_bucket': 'assemblyline-support',
                    'aws_region': 'us-east-1'
                }
            }
        },
        'repositories': {
            'realms': {
                # This defines how the core server will connect to the different repos
                #    Creds should be well defined in this section because updates will happen automatically
                #    therefore we wont be able to ask for password for each repo.
                #
                #    When user/password is use, we will put that in directly inside the git remote
                #    When public key is used, we will create an .ssh/config file for the
                #        realm and write the key to a file
                'bitbucket': {
                    'url': 'https://bitbucket.org/cse-assemblyline/',
                    'branch': 'prod_3.2',
                    'user': None,
                    'password': None,
                    'key': None
                }
            },
            'repos': {
                'al_ui': {
                    'realm': 'bitbucket'
                },
                'assemblyline': {
                    'realm': 'bitbucket'
                }
            }


        },
        # global apt or pip packages to install on every node that are not really
        # dependencies but are useful to have.
        'supplementary_packages': {
            'apt': [
                'iotop',
                'sysstat',
                'byobu',
            ],
            'pip': [
                'ipython<6.0.0'
            ],
        },
        'pip_index_url': ''
    },

    'logging': {
        'directory': '/opt/al/var/log',
        'log_to_console': True,
        'log_to_file': True,
        'log_to_syslog': False,
        'logserver': {
            'node': None,
            'kibana': {
                'dashboards': [
                    "AL-Logs",
                    "AL-Metrics",
                    "Cluster-Overview",
                    "Riak-Cluster-Health",
                    "SOLR-Shard-Statistics",
                    "UI-Audit-Logs"
                ],
                'extra_viz': [],
                'extra_indices': [],
                'host': '',
                'password': 'changeme',
                'port': 443,
                'scheme': 'https'
            },
            'elasticsearch': {
                'heap_size': 2,
                'index_ttl': {
                    'audit': 30,
                    'riak': 15,
                    'logs': 7,
                    'solr': 15,
                    'al_metrics': 30,
                    'system_metrics': 7,
                }
            },
            'ssl': {
                'crt': None,
                'key': None
            }
        },
        'syslog_ip': None
    },

    'monitoring': {
        'harddrive': True
    },

    'services': {
        'categories': [
            'Antivirus',
            'External',
            'Extraction',
            'Filtering',
            'Networking',
            'Static Analysis',
            'System'
        ],
        'flex_blacklist': ['Sync'],
        'limits': {
            'max_extracted': 500,
            'max_supplementary': 500,
        },
        'stages': [
            'SETUP', 'FILTER', 'EXTRACT', 'CORE', 'SECONDARY', 'POST', 'TEARDOWN'
        ],
        'system_category': 'System',
        'timeouts': {
            'default': 60,
        },
        'master_list': {
            # e.g.
            # 'ServiceName': {
            #     'class_name': 'ClassNameForTheService',
            #     'repo': 'name_of_the_repo_in_the_realm',
            #     'realm': 'realm_where_the_repo_is_located',
            #     'config': { # config override block },
            #     'install_by_default': True  # Will the service installer be called when setting up a worker
            #     'enabled': True,  # Will the service be enabled by default in the system
            #     'depends': {
            #         'repo': 'name_of_the_depends_repo',
            #         'realm': 'realm_where_the_depend_repo_is_located'
            #     }
            # }
            'APKaye': {
                'class_name': 'APKaye',
                'repo': 'alsvc_apkaye',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'Avg': {
                'class_name': 'Avg',
                'repo': 'alsvc_avg',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': False,
                'enabled': False
            },
            'Beaver': {
                'class_name': 'Beaver',
                'repo': 'alsvc_beaver',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'Binja': {
                'class_name': 'Binja',
                'repo': 'alsvc_binja',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': False,
                'enabled': False
            },
            'BitDefender': {
                'class_name': 'BitDefender',
                'repo': 'alsvc_bitdefender',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': False,
                'enabled': False
            },
            'CFMD': {
                'class_name': 'CFMD',
                'repo': 'alsvc_cfmd',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'Characterize': {
                'class_name': 'Characterize',
                'repo': 'alsvc_characterize',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'Cleaver': {
                'class_name': 'Cleaver',
                'repo': 'alsvc_cleaver',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'ConfigDecoder': {
                'class_name': 'ConfigDecoder',
                'repo': 'alsvc_configdecoder',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'CrowBar': {
                'class_name': 'CrowBar',
                'repo': 'alsvc_crowbar',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'Cuckoo': {
                'class_name': 'Cuckoo',
                'repo': 'alsvc_cuckoo',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'Espresso': {
                'class_name': 'Espresso',
                'repo': 'alsvc_espresso',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'Extract': {
                'class_name': 'Extract',
                'repo': 'alsvc_extract',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'FrankenStrings': {
                'class_name': 'FrankenStrings',
                'repo': 'alsvc_frankenstrings',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'FSecure': {
                'class_name': 'FSecure',
                'repo': 'alsvc_fsecure',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'KasperskyIcap': {
                'class_name': 'KasperskyIcap',
                'repo': 'alsvc_kaspersky',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'McAfee': {
                'class_name': 'McAfee',
                'repo': 'alsvc_mcafee',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': False,
                'enabled': False
            },
            'MetaPeek': {
                'class_name': 'MetaPeek',
                'repo': 'alsvc_metapeek',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'MetaDefender': {
                'class_name': 'MetaDefender',
                'repo': 'alsvc_metadefender',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'NSRL': {
                'class_name': 'NSRL',
                'repo': 'alsvc_nsrl',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'Oletools': {
                'class_name': 'Oletools',
                'repo': 'alsvc_oletools',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'PDFId': {
                'class_name': 'PDFId',
                'repo': 'alsvc_pdfid',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'PeePDF': {
                'class_name': 'PeePDF',
                'repo': 'alsvc_peepdf',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'PEFile': {
                'class_name': 'PEFile',
                'repo': 'alsvc_pefile',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'SigCheck': {
                'class_name': 'SigCheck',
                'repo': 'alsvc_sigcheck',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': False,
                'enabled': False
            },
            'Suricata': {
                'class_name': 'Suricata',
                'repo': 'alsvc_suricata',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },            
            'Swiffer': {
                'class_name': 'Swiffer',
                'repo': 'alsvc_swiffer',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'Symantec': {
                'class_name': 'Symantec',
                'repo': 'alsvc_symantec',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': False
            },
            'Sync': {
                'class_name': 'Sync',
                'repo': 'alsvc_sync',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'TagCheck': {
                'class_name': 'TagCheck',
                'repo': 'alsvc_tagcheck',
                'realm': 'bitbucket',
                "config": {},
                'install_by_default': True,
                'enabled': True
            },
            'TorrentSlicer': {
                'class_name': 'TorrentSlicer',
                'repo': 'alsvc_torrentslicer',
                'realm': 'bitbucket',
                "config": {},
                'install_by_default': True,
                'enabled': True
            },
            'Unpacker': {
                'class_name': 'Unpacker',
                'repo': 'alsvc_unpacker',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
            'VirusTotalDynamic': {
                'class_name': 'VirusTotalDynamic',
                'repo': 'alsvc_virustotal_dynamic',
                'realm': 'bitbucket',
                "config": {},
                'install_by_default': True,
                'enabled': False
            },
            'VirusTotalStatic': {
                'class_name': 'VirusTotalStatic',
                'repo': 'alsvc_virustotal_static',
                'realm': 'bitbucket',
                "config": {},
                'install_by_default': True,
                'enabled': False
            },
            'Yara': {
                'class_name': 'Yara',
                'repo': 'alsvc_yara',
                'realm': 'bitbucket',
                'config': {},
                'install_by_default': True,
                'enabled': True
            },
        },
    },

    # any site specifc / custom config can be stored in this dictionary
    # as long as it is json serializable
    'sitespecific': {},

    'statistics': {
        'submission_meta_fields': [
            'submission.submitter'
        ],
        'alert_statistics_fields': [
            'filename',
            'md5',
            'owner',
            'al_attrib',
            'al_av',
            'al_domain',
            'al_ip',
            'summary',
            'yara'
        ]
    },

    'submissions': {
        'decode_file': 'assemblyline.al.common.codec.decode_file',
        'max': {
            'priority': 10000,
            'size': 104857600,
        },
        'password': 'Int3rn@lP4s$',
        'ttl': 15,  # Days.
        'url': "https://localhost:443",
        'user': 'internal',
        'working_dir': '/opt/al/tmp/submission',
    },

    'system': {
        'classification': {
            'engine': 'assemblyline.al.common.classification.Classification',
            'definition': {
                "levels": [
                    {
                        "name": "UNRESTRICTED",
                        "lvl": 100,
                        "short_name": "U",
                        "aliases": [],
                        "description": "Default UNRESTRICTED classification.",
                        "css": {
                            "banner": "alert-default",
                            "label": "label-default",
                            "text": "text-muted"
                        }
                    },
                    {
                        "name": "RESTRICTED",
                        "lvl": 200,
                        "short_name": "R",
                        "aliases": [],
                        "description": "Default RESTRICTED classification.",
                        "css": {
                            "banner": "alert-danger",
                            "label": "label-danger",
                            "text": "text-danger"
                        }
                    },

                ],
                "required": [],
                "groups": [],
                "subgroups": [],
                "unrestricted": "U",
                "restricted": "R",
                "enforce": False
            }
        },
        'constants': 'assemblyline.common.constants',
        'country_code_map': 'assemblyline.common.null.CountryCodeMap',
        'internal_repository': {
            'url': 'http://localhost/git/',
            'branch': 'prod_3.2'
        },
        'load_config_from_riak': True,
        'name': 'default',
        'organisation': 'ACME',
        'password': None,
        'root': '/opt/al',
        'update_interval': 5,
        'use_proxy': True,
        'user': 'al',  # The system (linux) user AL runs as.
        'yara': {
            'externals': ['submitter', 'mime', 'tag'],
            'importer': "assemblyline.common.yara.YaraImporter",
            'parser': 'assemblyline.common.yara.YaraParser',
        }
    },

    'ui': {
        'allow_raw_downloads': True,
        'allowed_checkout_range': "0.0.0.0/0",
        'audit': True,
        'context': 'al_ui.site_specific.context',
        'debug': False,
        'download_encoding': 'cart',
        'email': None,
        'enforce_quota': False,
        'fqdn': 'assemblyline.localhost',  # import if you are using SSL/certs
        'install_path': '/opt/al/pkg',
        'rsa_key_size': 2048,
        'secret_key': '<put your own key here!>',
        'session_duration': 60 * 60,  # 1 Hour in seconds
        'ssl': {
            'enabled': True,
            'certs': {
                'autogen': True,  # autogenerate self signed certs
                'ca': None,
                'crl': None,
                'crt': None,
                'key': None,
                'tc': None
            }
        },
        'tos': None,
        'tos_lockout': False,
        'uwsgi': {
            'max_requests_per_worker': 128,
            'max_workers': 128,
            'start_workers': 16,
            'threads': 4
        }
    },

    'workers': {
        'default_profile': 'al-worker-default',
        'install_kvm': True,
        'nodes': ['localhost'],
        'proxy_redis': True,
        'virtualmachines': {
            'disk_root': '/opt/al/vmm/disks',
            'use_parent_as_datastore': False,
            'use_parent_as_queue': False,
            'master_list': {
                # 'BitDefender': make_vm_dict('BitDefender', 2048, 2, 43200,
                #                             "bitdefender.001.qcow2", 'linux', 'ubuntutrusty', 4),
                # 'McAfee': make_vm_dict('McAfee', 2048, 2, 86400,
                #                        "mcafee.001.qcow2", 'linux', 'ubuntutrusty', 3),
            }

        },
    }
}

seed = DEFAULT_SEED.copy()


if __name__ == '__main__':
    import sys

    if "json" in sys.argv:
        import json
        print json.dumps(seed)
    else:
        import pprint
        pprint.pprint(seed)
