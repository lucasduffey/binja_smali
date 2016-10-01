# installation
```
'''
This will be deprecated in favor of plugin.json when binja plugin API is more mature

1) cd ~/.binaryninja/plugins/
2) git clone https://github.com/lucasduffey/smaliBinja_python
3) echo "import smaliBinja_python" > wrapper.py
'''

import smaliBinja_python

```

# about
* apkView.py - carves out the dex file, then overwrites the view with it
* dexView.py - responsible for rendering the dexView + dex arch in binary ninja
* dexFile.py - this deals with the dex file structure

# binja relevant issues
* container format support: https://github.com/Vector35/binaryninja-api/issues/133
* structure UI: https://github.com/Vector35/binaryninja-api/issues/269
* block highlighting apis: https://github.com/Vector35/binaryninja-api/issues/417
* split python plugins from UI thread: https://github.com/Vector35/binaryninja-api/issues/390
* C++ plugin docs: https://github.com/Vector35/binaryninja-api/issues/452

# wishlist
* function tray UI should also support objects - have an object tree view

# thanks
* special thanks to ondreji (https://github.com/ondreji/dex_parser/blob/master/dex.py)
