# THIS FILE IS AUTO-GENERATED. DO NOT MODIFY!!

# Copyright 2020-2023 Tauri Programme within The Commons Conservancy
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

-keep class net.kackman.secureelement.example.* {
  native <methods>;
}

-keep class net.kackman.secureelement.example.WryActivity {
  public <init>(...);

  void setWebView(net.kackman.secureelement.example.RustWebView);
  java.lang.Class getAppClass(...);
  java.lang.String getVersion();
}

-keep class net.kackman.secureelement.example.Ipc {
  public <init>(...);

  @android.webkit.JavascriptInterface public <methods>;
}

-keep class net.kackman.secureelement.example.RustWebView {
  public <init>(...);

  void loadUrlMainThread(...);
  void loadHTMLMainThread(...);
  void evalScript(...);
}

-keep class net.kackman.secureelement.example.RustWebChromeClient,net.kackman.secureelement.example.RustWebViewClient {
  public <init>(...);
}
