[app]
title = P/M
package.name = pm_messenger
package.domain = org.private
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
requirements = python3,kivy,cryptography,requests,urllib3
orientation = portrait
fullscreen = 1
android.permissions = INTERNET
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = False

[buildozer]
log_level = 2
