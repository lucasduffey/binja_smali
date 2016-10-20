# installation
```
# This will be deprecated in favor of plugin.json when binja plugin system is stable

cd ~/.binaryninja/plugins/
git clone https://github.com/lucasduffey/binja_smali
echo "import binja_smali" > wrapper.py
```

# about
* apkView.py - carves out the dex file, then overwrites the view with it
* dexView.py - responsible for rendering the dexView + dex arch in binary ninja
* dexFile.py - this deals with the dex file structure

# binja relevant issues
* container format support: https://github.com/Vector35/binaryninja-api/issues/133
* structure UI: https://github.com/Vector35/binaryninja-api/issues/269
* C++ plugin docs: https://github.com/Vector35/binaryninja-api/issues/452
* binary ninja only passes opcodes to the Architecture class - it can't access binaryView data, or pull string tables and other misc. data for dissembling purposes.

# (semi-)fixed binja issues
* split python plugins from UI thread: https://github.com/Vector35/binaryninja-api/issues/390
* block highlighting apis: https://github.com/Vector35/binaryninja-api/issues/417

# wishlist
* function tray UI should also support objects - have an object tree view
* how will decompiled view be handled?

# thanks
* https://github.com/ondreji/dex_parser/blob/master/dex.py
* https://github.com/androguard/androguard
