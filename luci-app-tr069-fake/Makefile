# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI TR-069 Fake sandbox configuration
LUCI_URL:=https://github.com/grislux55/nnrrwrt-packages/tree/main/luci-app-tr069-fake
LUCI_DEPENDS:=+luci-base +airoha-tr069-fake
LUCI_PKGARCH:=all

PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=grislux55 <jebchou.hg@gmail.com>
PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage: feed scanner marker; luci.mk generates the package rules.
