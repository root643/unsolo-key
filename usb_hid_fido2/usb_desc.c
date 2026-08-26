/*******************************************************************************
 * usb_desc.c
 * USB Descriptors for FIDO2 CTAPHID
 *******************************************************************************/

#include "usb_desc.h"

/* Device Descriptor */
const uint8_t  MyDevDescr[] =
{
    0x12,                                               // bLength
    0x01,                                               // bDescriptorType (Device)
    0x10, 0x01,                                         // bcdUSB 1.10
    0x00,                                               // bDeviceClass
    0x00,                                               // bDeviceSubClass
    0x00,                                               // bDeviceProtocol
    DEF_USBD_UEP0_SIZE,                                 // bMaxPacketSize0
    (uint8_t)DEF_USB_VID, (uint8_t)(DEF_USB_VID >> 8),  // idVendor
    (uint8_t)DEF_USB_PID, (uint8_t)(DEF_USB_PID >> 8),  // idProduct
    0x00, DEF_IC_PRG_VER,                               // bcdDevice 1.00
    0x01,                                               // iManufacturer (String Index)
    0x02,                                               // iProduct (String Index)
    0x03,                                               // iSerialNumber (String Index)
    0x01,                                               // bNumConfigurations 1
};

/* Configuration Descriptor */
const uint8_t  MyCfgDescr[] =
{
    /* Configuration Descriptor */
    0x09,                           // bLength
    0x02,                           // bDescriptorType
    0x29, 0x00,                     // wTotalLength
    0x01,                           // bNumInterfaces
    0x01,                           // bConfigurationValue
    0x03,                           // iConfiguration (String Index)
    0x80,                           // bmAttributes
    0x23,                           // bMaxPower 70mA

    /* Interface Descriptor */
    0x09,                           // bLength
    0x04,                           // bDescriptorType (Interface)
    0x00,                           // bInterfaceNumber 0
    0x00,                           // bAlternateSetting
    0x02,                           // bNumEndpoints 2
    0x03,                           // bInterfaceClass (HID)
    0x00,                           // bInterfaceSubClass
    0x00,                           // bInterfaceProtocol
    0x00,                           // iInterface (String Index)

    /* HID Descriptor */
    0x09,                           // bLength
    0x21,                           // bDescriptorType
    0x11, 0x01,                     // bcdHID
    0x00,                           // bCountryCode
    0x01,                           // bNumDescriptors
    0x22,                           // bDescriptorType
    DEF_USBD_REPORT_DESC_LEN & 0xFF, DEF_USBD_REPORT_DESC_LEN >> 8, // wDescriptorLength

    /* Endpoint Descriptor */
    0x07,                           // bLength
    0x05,                           // bDescriptorType
    0x01,                           // bEndpointAddress: OUT Endpoint 1
    0x03,                           // bmAttributes
    0x40, 0x00,                     // wMaxPacketSize (64)
    0x05,                           // bInterval: 5mS

    /* Endpoint Descriptor */
    0x07,                           // bLength
    0x05,                           // bDescriptorType
    0x82,                           // bEndpointAddress: IN Endpoint 2
    0x03,                           // bmAttributes
    0x40, 0x00,                     // wMaxPacketSize (64)
    0x05,                           // bInterval: 5mS
};

/* HID Report Descriptor for FIDO2 CTAPHID */
const uint8_t  MyHIDReportDesc[ ] =
{
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01,       // Usage (U2F HID 0x01)
    0xA1, 0x01,       // Collection (Application)
    0x09, 0x20,       //   Usage (Data In 0x20)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x81, 0x02,       //   Input (Data,Var,Abs)
    0x09, 0x21,       //   Usage (Data Out 0x21)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x91, 0x02,       //   Output (Data,Var,Abs)
    0xC0              // End Collection
};

/* Language Descriptor */
const uint8_t  MyLangDescr[] =
{
    0x04, 0x03, 0x09, 0x04
};

/* Manufacturer Descriptor */
const uint8_t  MyManuInfo[] =
{
    0x0E, 0x03, 'A', 0, 'n', 0, 't', 0, 'i', 0, 'g', 0, 'r', 0
};

/* Product Information */
const uint8_t  MyProdInfo[] =
{
    0x12, 0x03, 'F', 0, 'I', 0, 'D', 0, 'O', 0, '2', 0, ' ', 0, 'K', 0, 'e', 0, 'y', 0
};

/* Serial Number Information */
const uint8_t  MySerNumInfo[] =
{
    0x16, 0x03, '0', 0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0
              , '6', 0, '7', 0, '8', 0, '9', 0
};
