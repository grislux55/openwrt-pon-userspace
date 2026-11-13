# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=airoha-tr069-fake
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_URL:=https://github.com/grislux55/openwrt-pon-userspace/tree/main/airoha-tr069-fake
PKG_MAINTAINER:=grislux55 <jebchou.hg@gmail.com>

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/airoha-tr069-fake
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=PON
  TITLE:=Dual-stack isolated TR-069 CWMP Fake sandbox daemon
  DEPENDS:=$(RUST_ARCH_DEPENDS) +libopenssl +ip-full
endef

define Package/airoha-tr069-fake/description
 Dual-stack isolated TR-069 (CWMP) sandbox client with persistent virtual
 TR-098/TR-181 data model, isolated netifd/firewall4 management channel,
 and sanitized /tmp audit logging.
endef

define Package/airoha-tr069-fake/conffiles
/etc/config/tr069_fake
/etc/tr069-fake/
endef

CARGO_PKG_VARS += \
	OPENSSL_NO_VENDOR=1 \
	OPENSSL_LIB_DIR=$(STAGING_DIR)/usr/lib \
	OPENSSL_INCLUDE_DIR=$(STAGING_DIR)/usr/include

CARGO_RUSTFLAGS+=-L$(STAGING_DIR)/usr/lib

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/Cargo.toml ./src/Cargo.lock ./src/LICENSE $(PKG_BUILD_DIR)/
	$(CP) ./src/src $(PKG_BUILD_DIR)/
endef

define Package/airoha-tr069-fake/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/airoha-tr069-fake $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/tr069-fake-apply $(1)/usr/libexec/tr069-fake-apply
	$(INSTALL_BIN) ./files/tr069-fake-ctl $(1)/usr/libexec/tr069-fake-ctl
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/tr069_fake.config $(1)/etc/config/tr069_fake
	chmod 0600 $(1)/etc/config/tr069_fake
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tr069-fake.init $(1)/etc/init.d/tr069-fake
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/tr069-fake.hotplug $(1)/etc/hotplug.d/iface/95-tr069-fake
	$(INSTALL_DIR) $(1)/etc/tr069-fake
endef

$(eval $(call RustBinPackage,airoha-tr069-fake))
$(eval $(call BuildPackage,airoha-tr069-fake))
