#!/usr/bin/bash
#adb shell pm clear com.natesworks.nbsoffline.v3
adb shell monkey -p com.natesworks.nbsoffline.v3 -c android.intent.category.LAUNCHER 1
npm run build
adb forward tcp:27042 tcp:27042
sleep 1
frida -p $(adb shell pidof com.natesworks.nbsoffline.v3) -H 127.0.0.1:27042 -l script.js
