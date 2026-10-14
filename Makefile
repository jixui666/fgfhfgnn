# theos Makefile — builds blocker.dylib
# Usage (on macOS with theos):  make clean && make
# Output: .theos/obj/.../blocker.dylib  (also copied to layout/usr/lib/)

# arm64e only: the target framework is arm64e and we rewrite ptrauth-stripped
# function pointers, so an arm64e slice is required.
ARCHS = arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = blocker
blocker_FILES = blocker.m
blocker_FRAMEWORKS = Foundation
blocker_INSTALL_PATH = /usr/lib
# NOTE: do NOT enable ARC (-fobjc-arc); the hook uses raw pointer arithmetic.

include $(THEOS_MAKE_PATH)/library.mk
