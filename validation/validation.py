from binaryninja import BinaryViewType, RepositoryManager
from pprint import pprint
import requests
import os

def list_plugins():
	mgr = RepositoryManager()
	pprint(mgr.plugins)

# CTFs to train against
# * https://github.com/xtiankisutsa/awesome-mobile-CTF
# * TODO: need a few simple ones to benchmark
#   * https://labs.mwrinfosecurity.com/system/assets/349/original/androidproject.apk
#   * https://github.com/artwyman/android_ctf/tree/master/signed_apks (?)

# su-ctf-2016 - Sharif_CTF.apk
apk_name, download_link = ("Sharif_CTF.apk", "https://drive.google.com/open?authuser=0&id=11b1yxihu1Q1QjNqPKwYHgPYQ1te_416W") # can't download from gdrive without auth

if not os.path.isfile(apk_name):
	#result = requests.get(testcase)
	print("Error: you don't have the %s testcase" % apk_name)
	exit()
else:
	print("TODO")

	# if "APK" isn't in BinaryViewType, the plugin has an error
	for bv_type in BinaryViewType:
		print bv_type # not seeing APK or dex

	# one option
	# how do you get bv without a type?
	bv = BinaryViewType['APK'].open(apk_name) # I think this worked
	if not bv:
		print("bv == None")
		exit()

	print("bv.platform: " + str(bv.platform)) # <platform: linux-x86>



	#br = BinaryReader(bv)


# check apk name - run tests and compare with historical results

#open herpderper.apk
#assert len(bv.functions) == 609 # TODO: update this
