#!/usr/bin/env python

import os
import sys
from time import sleep
from pyhashcat import Hashcat

def show_devices(backend_infos):
    if backend_infos is None:
        print("No backend")
        return

    for p in backend_infos:

        if p["platform_type"] == "cuda":
            version = p.get("cuda_driver_version", 0)
            print("CUDA API (CUDA %d.%d)" % (
                version / 1000,
                (version % 100) / 10))

        elif p["platform_type"] == "opencl":
            print("OpenCL API (%s) - Platform #%u [%s]\n" % (
                p.get("opencl_platform_version", 0),
                p.get("opencl_platforms_idx", 0) + 1,
                p.get("opencl_platform_vendor", 0)))

        else:
            print("Unknown Platform\n")

        for d in p["devices"]:

            if d.get("device_skipped", False):
                print("* Device #%u: %s, skipped\n" % (
                    d.get("device_id",0) + 1,
                    d.get("device_name",0)))
            else:
                print("* Device #%u: %s, %d/%d MB (%d MB allocatable), %uMCU\n" % (
                    d.get("device_id",0) + 1,
                    d.get("device_name",0),
                    d.get("device_available_mem",0) / 1024 / 1024,
                    d.get("device_global_mem",0)    / 1024 / 1024,
                    d.get("device_maxmem_alloc",0)  / 1024 / 1024,
                    d.get("device_processors",0)))


logs_buffer = []

def cracked_callback(sender, plain="", signal=None):
    print("[*] CRACKED", id(sender), "EVENT_CRACKER_HASH_CRACKED", plain)

def started_callback(sender, plain="", signal=None):
    print("[*] START", id(sender), "EVENT_CRACKER_STARTING")

def finished_callback(sender, plain="", signal=None):
    print("[*] FIN", id(sender), "EVENT_CRACKER_FINISHED")

def keyspace_callback(sender, plain="", signal=None):
    ks = sender.status_get_progress_end()
    print("[*] KEYSAPCE", id(sender), "EVENT_CALCULATED_WORDS_BASE", ks)

def any_callback(sender, plain="", signal=None):
    print("\033[90m[-] ANY", signal, sender.status_get_status_string(), plain,"\033[0m")

def log_callback_error(sender, plain="", signal=None):
    log = "ERROR %s" % sender.hashcat_status_get_log()
    logs_buffer.append(log)
    # print("[logger] %s" % log)
def log_callback_info(sender, plain="", signal=None):
    log = "INFO %s" % sender.hashcat_status_get_log()
    logs_buffer.append(log)
    # print("[logger] %s" % log)
def log_callback_warning(sender, plain="", signal=None):
    log = "WARNING %s" % sender.hashcat_status_get_log()
    logs_buffer.append(log)
    # print("[logger] %s" % log)
def log_callback_advice(sender, plain="", signal=None):
    log = "ADVICE %s" % sender.hashcat_status_get_log()
    logs_buffer.append(log)
    # print("[logger] %s" % log)


print("-------------------------------")
print("---- Simple pyhashcat Test ----")
print("-------------------------------")

hc = Hashcat()

# To view event types
# hc.event_types
print("[!] Hashcat object init with id:", id(hc))
print("[!] cb_id cracked:", hc.event_connect(callback=cracked_callback, signal="EVENT_CRACKER_HASH_CRACKED"))
print("[!] cb_id started:", hc.event_connect(callback=started_callback, signal="EVENT_CRACKER_STARTING"))
print("[!] cb_id finished:", hc.event_connect(callback=finished_callback, signal="EVENT_CRACKER_FINISHED"))
print("[!] cb_id keyspace:", hc.event_connect(callback=keyspace_callback, signal="EVENT_CALCULATED_WORDS_BASE"))
print("[!] cb_id log:", hc.event_connect(callback=log_callback_error, signal="EVENT_LOG_ERROR"))
print("[!] cb_id log:", hc.event_connect(callback=log_callback_info, signal="EVENT_LOG_INFO"))
print("[!] cb_id log:", hc.event_connect(callback=log_callback_warning, signal="EVENT_LOG_WARNING"))
print("[!] cb_id log:", hc.event_connect(callback=log_callback_advice, signal="EVENT_LOG_ADVICE"))
print("[!] cb_id any:", hc.event_connect(callback=any_callback, signal="ANY"))


# hc.hash = "md5_hash.txt" # BonjouR
# hc.hash = "ffc1aeeaa6027fa2a6f5bd099cfbdd99" # BonjouR
hc.hash = "f6971c95b22f3727225277bc942aa5f6" # Bonjour123
# hc.hash = '/home/hedroed/Projects/pwnagotchi/crack/NathanPhone_AP.hccapx'

# hc.mask = "lefromage?d?d?d"
# hc.mask = "B?1?1?1?1?1?1"
# hc.custom_charset_1 = "BonjuR"
# hc.custom_charset_1 = "?l?u"
hc.rules = ["/usr/share/doc/hashcat/rules/best64.rule"]
hc.rp_files_cnt = 1

# hc.dict1 = "/home/hedroed/Security/wordlists/rockyou.txt"
hc.dict1 = "./wl_small.txt"

# hc.quiet = True
# hc.keyspace = True
hc.potfile_disable = True
hc.outfile = os.path.join(os.path.expanduser('.'), "outfile.txt")
print("[+] Writing to ", hc.outfile)
hc.attack_mode = 0 # Dictionnary attack
# hc.attack_mode = 3 # Mask attack
hc.hash_mode = 0 # md5
# hc.hash_mode = 2500 # wpa2
hc.workload_profile = 2

# cracked = []
print("[+] Running hashcat")

try:
    err_code = hc.hashcat_session_execute(hc_path="/home/hedroed/tmp/hashcat/share/hashcat")
except SystemError as e:
    print("Exception %s" % e)

else:
    print("[+] Error code %s" % err_code)

    if err_code >= 0:
        # hashcat should be running in a background thread
        # wait for it to finishing cracking

        dev = hc.hashcat_backend_info()
        print("---"*20)
        print(dev)
        show_devices(dev)
        print("---"*20)

        while True:
            # do something else while cracking
            status = hc.status_get_status_string()

            progress = hc.status_get_progress_finished_percent()
            print("%.2f%%" % progress)
            # print("%.2f%%" % progress, end='\r', flush=True)

            # print(hc.hashcat_status_get_status())

            if status == "Cracked" or status == "Aborted" or status == "Exhausted":
                break

            sleep(.1)

    else:
        print("ERROR CODE %d" % err_code)

print("STATUS: ", hc.status_get_status_string())
print("Logs:")
print("\n".join(logs_buffer))

