# linux installation
```
# setup
cd ~/.binaryninja/plugins/
git clone https://github.com/lucasduffey/binja_smali
```

# about
* apkView.py - carves out the dex file, then overwrites the view with it
* dexView.py - responsible for rendering the dexView + dex arch in binary ninja
* dexFile.py - this deals with the dex file structure

# upstream binja issues
* [MAJOR] architecture doesn't have reference to the BinaryView https://github.com/Vector35/binaryninja-api/issues/551
* [MAJOR] SessionData doesn't persist. This would save the string table.
* [MEDIUM] container format support: https://github.com/Vector35/binaryninja-api/issues/133
* [MINOR] structure UI: https://github.com/Vector35/binaryninja-api/issues/269
* [MINOR] C++ plugin docs: https://github.com/Vector35/binaryninja-api/issues/452
* [MINOR] function tray UI tree view https://github.com/Vector35/binaryninja-api/issues/728
* [MINOR] decompiled source code view: https://github.com/Vector35/binaryninja-api/issues/541
```
decompiled source code view workarounds:
* show_plain_text_report
* show_html_report
* show_markdown_report
```


# (semi-)fixed binja issues
* split python plugins from UI thread: https://github.com/Vector35/binaryninja-api/issues/390
* block highlighting apis: https://github.com/Vector35/binaryninja-api/issues/417

# thanks
* https://github.com/ondreji/dex_parser/blob/master/dex.py
* https://github.com/androguard/androguard
