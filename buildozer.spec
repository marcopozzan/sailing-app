[app]
title           = SOAR
package.name    = soar
package.domain  = it.regolofarm
source.dir      = .
source.include_exts = py,png,jpg,kv,json,csv,ttf
version         = 1.5.0
requirements    = python3==3.11.9,kivy==2.3.0,pynmea2,certifi,pyjnius
orientation     = landscape
fullscreen      = 1
android.minapi  = 21
android.api     = 33
android.ndk     = 25c
android.archs   = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.permissions = INTERNET, ACCESS_NETWORK_STATE, CHANGE_NETWORK_STATE, WAKE_LOCK, WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE
log_level       = 2
warn_on_root    = 1

[buildozer]
log_level       = 2
warn_on_root    = 1
