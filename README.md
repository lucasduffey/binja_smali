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
* [CRITICAL] architecture doesn't have reference to the BinaryView https://github.com/Vector35/binaryninja-api/issues/551 (might have workaround)
* [CRITICAL] SessionData doesn't persist. This would save the string table. (might have workaround)
* [CRITICAL] container format support: https://github.com/Vector35/binaryninja-api/issues/133 (might have workaround)
* [LOW] function tray UI tree view https://github.com/Vector35/binaryninja-api/issues/728
* [LOW] decompiled source code view: https://github.com/Vector35/binaryninja-api/issues/541 (workaround documented below)
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
