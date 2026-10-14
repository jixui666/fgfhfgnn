# theos Makefile — builds blocker.dylib
# Usage (on macOS with theos):  make clean && make
# Output: .theos/obj/.../blocker.dylib  (also copied to layout/usr/lib/)

ARCHS = arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = blocker
blocker_FILES = blocker.m
blocker_LIBRARIES = substrate
blocker_FRAMEWORKS = Foundation
blocker_INSTALL_PATH = /usr/lib
# Modern Xcode ld64 defaults to shared-cache-eligible output, which refuses to
# link CydiaSubstrate (a non-system dylib). Opt out of shared cache eligibility.
blocker_LDFLAGS = -Wl,-not_for_dyld_shared_cache
# NOTE: do NOT enable ARC (-fobjc-arc); blocker.m uses [self release] in a
# failing -init to stay correct under both MRC and ARC callers.

include $(THEOS_MAKE_PATH)/library.mk
