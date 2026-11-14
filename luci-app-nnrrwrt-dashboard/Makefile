# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI NNRRWrt optical gateway dashboard
LUCI_URL:=https://github.com/grislux55/nnrrwrt-packages/tree/main/luci-app-nnrrwrt-dashboard
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode
LUCI_PKGARCH:=all
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=grislux55 <jebchou.hg@gmail.com>
LUCI_MINIFY_CSS:=0

PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage: feed scanner marker; luci.mk generates the package rules.
