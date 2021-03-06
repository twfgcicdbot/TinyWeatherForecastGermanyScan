# source: https://github.com/Exodus-Privacy/exodus/blob/c365dfd9f5044f48bc5ddac794073ed664b3a82a/exodus/exodus/core/permissions_en.py
# license: GPLv3 https://github.com/Exodus-Privacy/exodus/blob/v1/LICENSE

AOSP_PERMISSIONS_EN = {
    "groups": {
        "android.permission-group.CALENDAR": {
            "description": "access your calendar",
            "description_ptr": "permgroupdesc_calendar",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99 .9 -1.99 2L3 19c0 1.1 .89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_calendar",
            "label": "Calendar",
            "label_ptr": "permgrouplab_calendar",
            "name": "android.permission-group.CALENDAR",
            "request_ptr": "permgrouprequest_calendar"
        },
        "android.permission-group.CALL_LOG": {
            "description": "read and write phone call log",
            "description_ptr": "permgroupdesc_calllog",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24.0\" viewBox=\"0 0 24.0 24.0\" width=\"24.0\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M16.01,14.48l-2.62,2.62c-2.75,-1.49 -5.01,-3.75 -6.5,-6.5l2.62,-2.62c0.24,-0.24 0.34,-0.58 0.27,-0.9L9.13,3.82c-0.09,-0.47 -0.5,-0.8 -0.98,-0.8L4,3.01c-0.56,0 -1.03,0.47 -1,1.03c0.17,2.91 1.04,5.63 2.43,8.01c1.57,2.69 3.81,4.93 6.5,6.5c2.38,1.39 5.1,2.26 8.01,2.43c0.56,0.03 1.03,-0.44 1.03,-1v-4.15c0,-0.48 -0.34,-0.89 -0.8,-0.98l-3.26,-0.65C16.58,14.14 16.24,14.24 16.01,14.48z\" fill=\"#000000\"/><path d=\"M12,8h10V6H12V8zM12,4h10V2H12V4zM22,10H12v2h10V10z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_call_log",
            "label": "Call logs",
            "label_ptr": "permgrouplab_calllog",
            "name": "android.permission-group.CALL_LOG",
            "request_ptr": "permgrouprequest_calllog"
        },
        "android.permission-group.CAMERA": {
            "description": "take pictures and record video",
            "description_ptr": "permgroupdesc_camera",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20,5h-3.17L15,3H9L7.17,5H4C2.9,5 2,5.9 2,7v12c0,1.1 0.9,2 2,2h16c1.1,0 2,-0.9 2,-2V7C22,5.9 21.1,5 20,5zM20,19H4V7h16V19z\" fill=\"#000000\"/><path d=\"M12,9c-2.21,0 -4,1.79 -4,4c0,2.21 1.79,4 4,4s4,-1.79 4,-4C16,10.79 14.21,9 12,9z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_camera",
            "label": "Camera",
            "label_ptr": "permgrouplab_camera",
            "name": "android.permission-group.CAMERA",
            "request_ptr": "permgrouprequest_camera"
        },
        "android.permission-group.CONTACTS": {
            "description": "access your contacts",
            "description_ptr": "permgroupdesc_contacts",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M4,1h16v2h-16z\" fill=\"#000000\"/><path d=\"M4,21h16v2h-16z\" fill=\"#000000\"/><path d=\"M20,5H4C2.9,5 2,5.9 2,7v10c0,1.1 0.9,2 2,2h2h12h2c1.1,0 2,-0.9 2,-2V7C22,5.9 21.1,5 20,5zM8.21,17c0.7,-0.47 2.46,-1 3.79,-1s3.09,0.53 3.79,1H8.21zM20,17h-2c0,-1.99 -4,-3 -6,-3s-6,1.01 -6,3H4V7h16V17z\" fill=\"#000000\"/><path d=\"M12,13.5c1.66,0 3,-1.34 3,-3c0,-1.66 -1.34,-3 -3,-3s-3,1.34 -3,3C9,12.16 10.34,13.5 12,13.5zM12,9.5c0.55,0 1,0.45 1,1s-0.45,1 -1,1s-1,-0.45 -1,-1S11.45,9.5 12,9.5z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_contacts",
            "label": "Contacts",
            "label_ptr": "permgrouplab_contacts",
            "name": "android.permission-group.CONTACTS",
            "request_ptr": "permgrouprequest_contacts"
        },
        "android.permission-group.LOCATION": {
            "description": "access this device's location",
            "description_ptr": "permgroupdesc_location",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12,2C8.13,2 5,5.13 5,9c0,5.25 7,13 7,13s7,-7.75 7,-13C19,5.13 15.87,2 12,2zM7,9c0,-2.76 2.24,-5 5,-5s5,2.24 5,5c0,2.88 -2.88,7.19 -5,9.88C9.92,16.21 7,11.85 7,9z\" fill=\"#000000\"/><path d=\"M12,9m-2.5,0a2.5,2.5 0,1 1,5 0a2.5,2.5 0,1 1,-5 0\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_location",
            "label": "Location",
            "label_ptr": "permgrouplab_location",
            "name": "android.permission-group.LOCATION",
            "request_ptr": "permgrouprequest_location"
        },
        "android.permission-group.MICROPHONE": {
            "description": "record audio",
            "description_ptr": "permgroupdesc_microphone",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12,14c1.66,0 3,-1.34 3,-3V5c0,-1.66 -1.34,-3 -3,-3S9,3.34 9,5v6C9,12.66 10.34,14 12,14zM11,5c0,-0.55 0.45,-1 1,-1s1,0.45 1,1v6c0,0.55 -0.45,1 -1,1s-1,-0.45 -1,-1V5z\" fill=\"#000000\"/><path d=\"M17,11c0,2.76 -2.24,5 -5,5s-5,-2.24 -5,-5H5c0,3.53 2.61,6.43 6,6.92V21h2v-3.08c3.39,-0.49 6,-3.39 6,-6.92H17z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_microphone",
            "label": "Microphone",
            "label_ptr": "permgrouplab_microphone",
            "name": "android.permission-group.MICROPHONE",
            "request_ptr": "permgrouprequest_microphone"
        },
        "android.permission-group.PHONE": {
            "description": "make and manage phone calls",
            "description_ptr": "permgroupdesc_phone",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27 .67 -.36 1.02-.24 1.12 .37 2.33 .57 3.57 .57 .55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55 .45 -1 1-1h3.5c.55 0 1 .45 1 1 0 1.25 .2 2.45 .57 3.57 .11 .35 .03 .74-.25 1.02l-2.2 2.2z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_phone_calls",
            "label": "Phone",
            "label_ptr": "permgrouplab_phone",
            "name": "android.permission-group.PHONE",
            "request_ptr": "permgrouprequest_phone"
        },
        "android.permission-group.SENSORS": {
            "description": "access sensor data about your vital signs",
            "description_ptr": "permgroupdesc_sensors",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M13.49 5.48c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm-3.6 13.9l1-4.4 2.1 2v6h2v-7.5l-2.1-2 .6-3c1.3 1.5 3.3 2.5 5.5 2.5v-2c-1.9 0-3.5-1-4.3-2.4l-1-1.6c-.4-.6-1-1-1.7-1-.3 0-.5 .1 -.8 .1 l-5.2 2.2v4.7h2v-3.4l1.8-.7-1.6 8.1-4.9-1-.4 2 7 1.4z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_sensors",
            "label": "Body Sensors",
            "label_ptr": "permgrouplab_sensors",
            "name": "android.permission-group.SENSORS",
            "request_ptr": "permgrouprequest_sensors"
        },
        "android.permission-group.SMS": {
            "description": "send and view SMS messages",
            "description_ptr": "permgroupdesc_sms",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20,2H4C2.9,2 2,2.9 2,4v18l4.75,-4h14C21.1,18 22,17.1 22,16V4C22,2.9 21.1,2 20,2zM20,16H4V4h16V16zM9,11H7V9h2V11zM17,11h-2V9h2V11zM13,11h-2V9h2V11z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_sms",
            "label": "SMS",
            "label_ptr": "permgrouplab_sms",
            "name": "android.permission-group.SMS",
            "request_ptr": "permgrouprequest_sms"
        },
        "android.permission-group.STORAGE": {
            "description": "access photos, media, and files on your device",
            "description_ptr": "permgroupdesc_storage",
            "icon": "<?xml version=\"1.0\" ?><svg height=\"24\" viewBox=\"0 0 24 24\" width=\"24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M20,6h-8l-2,-2H4C2.9,4 2.01,4.9 2.01,6L2,18c0,1.1 0.9,2 2,2h16c1.1,0 2,-0.9 2,-2V8C22,6.9 21.1,6 20,6zM20,18H4V8h16V18z\" fill=\"#000000\"/></svg>",
            "icon_ptr": "perm_group_storage",
            "label": "Storage",
            "label_ptr": "permgrouplab_storage",
            "name": "android.permission-group.STORAGE",
            "request_ptr": "permgrouprequest_storage"
        }
    },
    "permissions": {
        "android.intent.category.MASTER_CLEAR.permission.C2D_MESSAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.intent.category.MASTER_CLEAR.permission.C2D_MESSAGE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCEPT_HANDOVER": {
            "description": "Allows the app to continue a call which was started in another app.",
            "description_ptr": "permdesc_acceptHandovers",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCEPT_HANDOVER",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous"
        },
        "android.permission.ACCESS_AMBIENT_LIGHT_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_AMBIENT_LIGHT_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.ACCESS_BROADCAST_RADIO": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_BROADCAST_RADIO",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_CACHE_FILESYSTEM": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_CACHE_FILESYSTEM",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_CHECKIN_PROPERTIES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_CHECKIN_PROPERTIES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "description": "This app can get your location based on network sources such as cell towers and Wi-Fi networks. These location services must be turned on and available on your phone for the app to be able to use them.",
            "description_ptr": "permdesc_accessCoarseLocation",
            "label": "access approximate location\n            (network-based)",
            "label_ptr": "permlab_accessCoarseLocation",
            "name": "android.permission.ACCESS_COARSE_LOCATION",
            "permission_group": "android.permission-group.LOCATION",
            "protection_level": "dangerous|instant"
        },
        "android.permission.ACCESS_CONTENT_PROVIDERS_EXTERNALLY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_CONTENT_PROVIDERS_EXTERNALLY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_DRM_CERTIFICATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_DRM_CERTIFICATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            "description": "This app can get your location based on GPS or network location sources such as cell towers and Wi-Fi networks. These location services must be turned on and available on your phone for the app to be able to use them. This may increase battery consumption.",
            "description_ptr": "permdesc_accessFineLocation",
            "label": "access precise location (GPS and\n            network-based)",
            "label_ptr": "permlab_accessFineLocation",
            "name": "android.permission.ACCESS_FINE_LOCATION",
            "permission_group": "android.permission-group.LOCATION",
            "protection_level": "dangerous|instant"
        },
        "android.permission.ACCESS_FM_RADIO": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_FM_RADIO",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_IMS_CALL_SERVICE": {
            "description": "Allows the app to use the IMS service to make calls without your intervention.",
            "description_ptr": "permdesc_accessImsCallService",
            "label": "access IMS call service",
            "label_ptr": "permlab_accessImsCallService",
            "name": "android.permission.ACCESS_IMS_CALL_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_INPUT_FLINGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_INPUT_FLINGER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_INSTANT_APPS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_INSTANT_APPS",
            "permission_group": "",
            "protection_level": "signature|installer|verifier"
        },
        "android.permission.ACCESS_KEYGUARD_SECURE_STORAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_KEYGUARD_SECURE_STORAGE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS": {
            "description": "Allows the app to access\n                extra location provider commands.    This may allow the app to interfere\n                with the operation of the GPS or other location sources.",
            "description_ptr": "permdesc_accessLocationExtraCommands",
            "label": "access extra location provider commands",
            "label_ptr": "permlab_accessLocationExtraCommands",
            "name": "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.ACCESS_LOWPAN_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_LOWPAN_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_MOCK_LOCATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_MOCK_LOCATION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_MTP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_MTP",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_NETWORK_CONDITIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_NETWORK_CONDITIONS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_NETWORK_STATE": {
            "description": "Allows the app to view\n            information about network connections such as which networks exist and are\n            connected.",
            "description_ptr": "permdesc_accessNetworkState",
            "label": "view network connections",
            "label_ptr": "permlab_accessNetworkState",
            "name": "android.permission.ACCESS_NETWORK_STATE",
            "permission_group": "",
            "protection_level": "normal|instant"
        },
        "android.permission.ACCESS_NOTIFICATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_NOTIFICATIONS",
            "permission_group": "",
            "protection_level": "signature|privileged|appop"
        },
        "android.permission.ACCESS_NOTIFICATION_POLICY": {
            "description": "Allows the app to read and write Do Not Disturb configuration.",
            "description_ptr": "permdesc_access_notification_policy",
            "label": "access Do Not Disturb",
            "label_ptr": "permlab_access_notification_policy",
            "name": "android.permission.ACCESS_NOTIFICATION_POLICY",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.ACCESS_PDB_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_PDB_STATE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_SHORTCUTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_SHORTCUTS",
            "permission_group": "",
            "protection_level": "signature|textClassifier"
        },
        "android.permission.ACCESS_SURFACE_FLINGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_SURFACE_FLINGER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_UCE_OPTIONS_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_UCE_OPTIONS_SERVICE",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_UCE_PRESENCE_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_UCE_PRESENCE_SERVICE",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "signature|privileged"
        },
        "android.permission.ACCESS_VOICE_INTERACTION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_VOICE_INTERACTION_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_VR_MANAGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_VR_MANAGER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACCESS_VR_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCESS_VR_STATE",
            "permission_group": "",
            "protection_level": "signature|preinstalled"
        },
        "android.permission.ACCESS_WIFI_STATE": {
            "description": "Allows the app to view information\n            about Wi-Fi networking, such as whether Wi-Fi is enabled and name of\n            connected Wi-Fi devices.",
            "description_ptr": "permdesc_accessWifiState",
            "label": "view Wi-Fi connections",
            "label_ptr": "permlab_accessWifiState",
            "name": "android.permission.ACCESS_WIFI_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.ACCESS_WIMAX_STATE": {
            "description": "Allows the app to determine whether\n         WiMAX is enabled and information about any WiMAX networks that are\n         connected. ",
            "description_ptr": "permdesc_accessWimaxState",
            "label": "connect and disconnect from WiMAX",
            "label_ptr": "permlab_accessWimaxState",
            "name": "android.permission.ACCESS_WIMAX_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.ACCOUNT_MANAGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACCOUNT_MANAGER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ACTIVITY_EMBEDDING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ACTIVITY_EMBEDDING",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.ALLOCATE_AGGRESSIVE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ALLOCATE_AGGRESSIVE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ALLOW_ANY_CODEC_FOR_PLAYBACK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ALLOW_ANY_CODEC_FOR_PLAYBACK",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.ANSWER_PHONE_CALLS": {
            "description": "Allows the app to answer an incoming phone call.",
            "description_ptr": "permdesc_answerPhoneCalls",
            "label": "answer phone calls",
            "label_ptr": "permlab_answerPhoneCalls",
            "name": "android.permission.ANSWER_PHONE_CALLS",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous|runtime"
        },
        "android.permission.ASEC_ACCESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ASEC_ACCESS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ASEC_CREATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ASEC_CREATE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ASEC_DESTROY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ASEC_DESTROY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ASEC_MOUNT_UNMOUNT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ASEC_MOUNT_UNMOUNT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.ASEC_RENAME": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.ASEC_RENAME",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.AUTHENTICATE_ACCOUNTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.AUTHENTICATE_ACCOUNTS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.BACKUP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BACKUP",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BATTERY_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BATTERY_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.BIND_ACCESSIBILITY_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_APPWIDGET": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_APPWIDGET",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_AUTOFILL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_AUTOFILL",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_AUTOFILL_FIELD_CLASSIFICATION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_AUTOFILL_FIELD_CLASSIFICATION_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_AUTOFILL_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_AUTOFILL_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_CACHE_QUOTA_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CACHE_QUOTA_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_CALL_REDIRECTION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CALL_REDIRECTION_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_CARRIER_MESSAGING_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CARRIER_MESSAGING_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_CARRIER_SERVICES": {
            "description": "Allows the holder to bind to carrier services. Should never be needed for normal apps.",
            "description_ptr": "permdesc_bindCarrierServices",
            "label": "bind to carrier services",
            "label_ptr": "permlab_bindCarrierServices",
            "name": "android.permission.BIND_CARRIER_SERVICES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_CHOOSER_TARGET_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CHOOSER_TARGET_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_COMPANION_DEVICE_MANAGER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_COMPANION_DEVICE_MANAGER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_CONDITION_PROVIDER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_CONNECTION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_CONNECTION_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_DEVICE_ADMIN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_DEVICE_ADMIN",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_DIRECTORY_SEARCH": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_DIRECTORY_SEARCH",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_DREAM_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_DREAM_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_EUICC_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_EUICC_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_IMS_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_IMS_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged|vendorPrivileged"
        },
        "android.permission.BIND_INCALL_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_INCALL_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_INPUT_METHOD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_INPUT_METHOD",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_INTENT_FILTER_VERIFIER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_INTENT_FILTER_VERIFIER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_JOB_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_JOB_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_KEYGUARD_APPWIDGET": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_KEYGUARD_APPWIDGET",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_MIDI_DEVICE_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_MIDI_DEVICE_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_NETWORK_RECOMMENDATION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_NETWORK_RECOMMENDATION_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_NFC_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_NFC_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_NOTIFICATION_ASSISTANT_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_NOTIFICATION_ASSISTANT_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_PACKAGE_VERIFIER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_PACKAGE_VERIFIER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_PRINT_RECOMMENDATION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_PRINT_RECOMMENDATION_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_PRINT_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_PRINT_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_PRINT_SPOOLER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_PRINT_SPOOLER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_QUICK_SETTINGS_TILE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_QUICK_SETTINGS_TILE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_REMOTEVIEWS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_REMOTEVIEWS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_REMOTE_DISPLAY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_REMOTE_DISPLAY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_RESOLVER_RANKER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_RESOLVER_RANKER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_ROUTE_PROVIDER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_ROUTE_PROVIDER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_RUNTIME_PERMISSION_PRESENTER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_RUNTIME_PERMISSION_PRESENTER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_SCREENING_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_SCREENING_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_SETTINGS_SUGGESTIONS_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_SETTINGS_SUGGESTIONS_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_SOUND_TRIGGER_DETECTION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_SOUND_TRIGGER_DETECTION_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TELECOM_CONNECTION_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_TELEPHONY_DATA_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TELEPHONY_DATA_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TELEPHONY_NETWORK_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TELEPHONY_NETWORK_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TEXTCLASSIFIER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TEXTCLASSIFIER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TEXT_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TEXT_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TRUST_AGENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TRUST_AGENT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_TV_INPUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TV_INPUT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_TV_REMOTE_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_TV_REMOTE_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BIND_VOICE_INTERACTION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_VOICE_INTERACTION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_VPN_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_VPN_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_VR_LISTENER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_VR_LISTENER_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BIND_WALLPAPER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BIND_WALLPAPER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BLUETOOTH": {
            "description": "Allows the app to view the\n            configuration of the Bluetooth on the phone, and to make and accept\n            connections with paired devices.",
            "description_ptr": "permdesc_bluetooth",
            "label": "pair with Bluetooth devices",
            "label_ptr": "permlab_bluetooth",
            "name": "android.permission.BLUETOOTH",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.BLUETOOTH_ADMIN": {
            "description": "Allows the app to configure\n            the local Bluetooth phone, and to discover and pair with remote devices.",
            "description_ptr": "permdesc_bluetoothAdmin",
            "label": "access Bluetooth settings",
            "label_ptr": "permlab_bluetoothAdmin",
            "name": "android.permission.BLUETOOTH_ADMIN",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.BLUETOOTH_MAP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BLUETOOTH_MAP",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BLUETOOTH_PRIVILEGED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BLUETOOTH_PRIVILEGED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BLUETOOTH_STACK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BLUETOOTH_STACK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BODY_SENSORS": {
            "description": "Allows the app to access data from sensors\n        that monitor your physical condition, such as your heart rate.",
            "description_ptr": "permdesc_bodySensors",
            "label": "access body sensors (like heart rate monitors)\n        ",
            "label_ptr": "permlab_bodySensors",
            "name": "android.permission.BODY_SENSORS",
            "permission_group": "android.permission-group.SENSORS",
            "protection_level": "dangerous"
        },
        "android.permission.BRICK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BRICK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BRIGHTNESS_SLIDER_USAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BRIGHTNESS_SLIDER_USAGE",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.BROADCAST_NETWORK_PRIVILEGED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BROADCAST_NETWORK_PRIVILEGED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.BROADCAST_PACKAGE_REMOVED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BROADCAST_PACKAGE_REMOVED",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BROADCAST_SMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BROADCAST_SMS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.BROADCAST_STICKY": {
            "description": "Allows the app to\n        send sticky broadcasts, which remain after the broadcast ends. Excessive\n        use may make the phone slow or unstable by causing it to use too\n        much memory.",
            "description_ptr": "permdesc_broadcastSticky",
            "label": "send sticky broadcast",
            "label_ptr": "permlab_broadcastSticky",
            "name": "android.permission.BROADCAST_STICKY",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.BROADCAST_WAP_PUSH": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.BROADCAST_WAP_PUSH",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CACHE_CONTENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CACHE_CONTENT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CALL_PHONE": {
            "description": "Allows the app to call phone numbers\n            without your intervention. This may result in unexpected charges or calls.\n            Note that this doesn't allow the app to call emergency numbers.\n            Malicious apps may cost you money by making calls without your\n            confirmation.",
            "description_ptr": "permdesc_callPhone",
            "label": "directly call phone numbers",
            "label_ptr": "permlab_callPhone",
            "name": "android.permission.CALL_PHONE",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous"
        },
        "android.permission.CALL_PRIVILEGED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CALL_PRIVILEGED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAMERA": {
            "description": "This app can take pictures and record videos using the camera at any time.",
            "description_ptr": "permdesc_camera",
            "label": "take pictures and videos",
            "label_ptr": "permlab_camera",
            "name": "android.permission.CAMERA",
            "permission_group": "android.permission-group.CAMERA",
            "protection_level": "dangerous|instant"
        },
        "android.permission.CAMERA_DISABLE_TRANSMIT_LED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAMERA_DISABLE_TRANSMIT_LED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAMERA_SEND_SYSTEM_EVENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAMERA_SEND_SYSTEM_EVENTS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAPTURE_AUDIO_HOTWORD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAPTURE_AUDIO_HOTWORD",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAPTURE_AUDIO_OUTPUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAPTURE_AUDIO_OUTPUT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAPTURE_TV_INPUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAPTURE_TV_INPUT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CAPTURE_VIDEO_OUTPUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CAPTURE_VIDEO_OUTPUT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CARRIER_FILTER_SMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CARRIER_FILTER_SMS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_ACCESSIBILITY_VOLUME": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_ACCESSIBILITY_VOLUME",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CHANGE_APP_IDLE_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_APP_IDLE_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_BACKGROUND_DATA_SETTING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_BACKGROUND_DATA_SETTING",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CHANGE_COMPONENT_ENABLED_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_CONFIGURATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_CONFIGURATION",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_HDMI_CEC_ACTIVE_SOURCE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_HDMI_CEC_ACTIVE_SOURCE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_LOWPAN_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_LOWPAN_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_NETWORK_STATE": {
            "description": "Allows the app to change the state of network connectivity.",
            "description_ptr": "permdesc_changeNetworkState",
            "label": "change network connectivity",
            "label_ptr": "permlab_changeNetworkState",
            "name": "android.permission.CHANGE_NETWORK_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.CHANGE_OVERLAY_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CHANGE_OVERLAY_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CHANGE_WIFI_MULTICAST_STATE": {
            "description": "Allows the app to receive\n            packets sent to all devices on a Wi-Fi network using multicast addresses,\n            not just your phone.    It uses more power than the non-multicast mode.",
            "description_ptr": "permdesc_changeWifiMulticastState",
            "label": "allow Wi-Fi Multicast reception",
            "label_ptr": "permlab_changeWifiMulticastState",
            "name": "android.permission.CHANGE_WIFI_MULTICAST_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.CHANGE_WIFI_STATE": {
            "description": "Allows the app to connect to and\n            disconnect from Wi-Fi access points and to make changes to device\n            configuration for Wi-Fi networks.",
            "description_ptr": "permdesc_changeWifiState",
            "label": "connect and disconnect from Wi-Fi",
            "label_ptr": "permlab_changeWifiState",
            "name": "android.permission.CHANGE_WIFI_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.CHANGE_WIMAX_STATE": {
            "description": "Allows the app to\n            connect the phone to and disconnect the phone from WiMAX networks.",
            "description_ptr": "permdesc_changeWimaxState",
            "label": "change WiMAX state",
            "label_ptr": "permlab_changeWimaxState",
            "name": "android.permission.CHANGE_WIMAX_STATE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.CLEAR_APP_CACHE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CLEAR_APP_CACHE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CLEAR_APP_GRANTED_URI_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CLEAR_APP_GRANTED_URI_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CLEAR_APP_USER_DATA": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CLEAR_APP_USER_DATA",
            "permission_group": "",
            "protection_level": "signature|installer"
        },
        "android.permission.CONFIGURE_DISPLAY_BRIGHTNESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONFIGURE_DISPLAY_BRIGHTNESS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.CONFIGURE_DISPLAY_COLOR_MODE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONFIGURE_DISPLAY_COLOR_MODE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CONFIGURE_WIFI_DISPLAY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONFIGURE_WIFI_DISPLAY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CONFIRM_FULL_BACKUP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONFIRM_FULL_BACKUP",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CONNECTIVITY_INTERNAL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONNECTIVITY_INTERNAL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONNECTIVITY_USE_RESTRICTED_NETWORKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONNECTIVITY_USE_RESTRICTED_NETWORKS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_DISPLAY_BRIGHTNESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_DISPLAY_BRIGHTNESS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CONTROL_DISPLAY_SATURATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_DISPLAY_SATURATION",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_INCALL_EXPERIENCE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_INCALL_EXPERIENCE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_KEYGUARD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_KEYGUARD",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CONTROL_LOCATION_UPDATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_LOCATION_UPDATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_REMOTE_APP_TRANSITION_ANIMATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_REMOTE_APP_TRANSITION_ANIMATIONS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_VPN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_VPN",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.CONTROL_WIFI_DISPLAY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CONTROL_WIFI_DISPLAY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.COPY_PROTECTED_DATA": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.COPY_PROTECTED_DATA",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CREATE_USERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CREATE_USERS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.CRYPT_KEEPER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.CRYPT_KEEPER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.DELETE_CACHE_FILES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DELETE_CACHE_FILES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.DELETE_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DELETE_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.DEVICE_POWER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DEVICE_POWER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.DIAGNOSTIC": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DIAGNOSTIC",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.DISABLE_HIDDEN_API_CHECKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DISABLE_HIDDEN_API_CHECKS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.DISABLE_INPUT_DEVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DISABLE_INPUT_DEVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.DISABLE_KEYGUARD": {
            "description": "Allows the app to disable the\n            keylock and any associated password security.    For example, the phone\n            disables the keylock when receiving an incoming phone call, then\n            re-enables the keylock when the call is finished.",
            "description_ptr": "permdesc_disableKeyguard",
            "label": "disable your screen lock",
            "label_ptr": "permlab_disableKeyguard",
            "name": "android.permission.DISABLE_KEYGUARD",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.DISPATCH_NFC_MESSAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DISPATCH_NFC_MESSAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.DISPATCH_PROVISIONING_MESSAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DISPATCH_PROVISIONING_MESSAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.DUMP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DUMP",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.DVB_DEVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.DVB_DEVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.EXPAND_STATUS_BAR": {
            "description": "Allows the app to expand or collapse the status bar.",
            "description_ptr": "permdesc_expandStatusBar",
            "label": "expand/collapse status bar",
            "label_ptr": "permlab_expandStatusBar",
            "name": "android.permission.EXPAND_STATUS_BAR",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.FACTORY_TEST": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FACTORY_TEST",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.FILTER_EVENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FILTER_EVENTS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.FLASHLIGHT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FLASHLIGHT",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.FORCE_BACK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FORCE_BACK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.FORCE_PERSISTABLE_URI_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FORCE_PERSISTABLE_URI_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.FORCE_STOP_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FORCE_STOP_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.FOREGROUND_SERVICE": {
            "description": "Allows the app to make use of foreground services.",
            "description_ptr": "permdesc_foregroundService",
            "label": "run foreground service",
            "label_ptr": "permlab_foregroundService",
            "name": "android.permission.FOREGROUND_SERVICE",
            "permission_group": "",
            "protection_level": "normal|instant"
        },
        "android.permission.FRAME_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FRAME_STATS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.FREEZE_SCREEN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.FREEZE_SCREEN",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GET_ACCOUNTS": {
            "description": "Allows the app to get\n            the list of accounts known by the phone.    This may include any accounts\n            created by applications you have installed.",
            "description_ptr": "permdesc_getAccounts",
            "label": "find accounts on the device",
            "label_ptr": "permlab_getAccounts",
            "name": "android.permission.GET_ACCOUNTS",
            "permission_group": "android.permission-group.CONTACTS",
            "protection_level": "dangerous"
        },
        "android.permission.GET_ACCOUNTS_PRIVILEGED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_ACCOUNTS_PRIVILEGED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.GET_APP_GRANTED_URI_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_APP_GRANTED_URI_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GET_APP_OPS_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_APP_OPS_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.GET_DETAILED_TASKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_DETAILED_TASKS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GET_INTENT_SENDER_INTENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_INTENT_SENDER_INTENT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GET_PACKAGE_SIZE": {
            "description": "Allows the app to retrieve its code, data, and cache sizes",
            "description_ptr": "permdesc_getPackageSize",
            "label": "measure app storage space",
            "label_ptr": "permlab_getPackageSize",
            "name": "android.permission.GET_PACKAGE_SIZE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.GET_PASSWORD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_PASSWORD",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GET_PROCESS_STATE_AND_OOM_SCORE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_PROCESS_STATE_AND_OOM_SCORE",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.GET_TASKS": {
            "description": "Allows the app to retrieve information\n             about currently and recently running tasks.    This may allow the app to\n             discover information about which applications are used on the device.",
            "description_ptr": "permdesc_getTasks",
            "label": "retrieve running apps",
            "label_ptr": "permlab_getTasks",
            "name": "android.permission.GET_TASKS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.GET_TOP_ACTIVITY_INFO": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GET_TOP_ACTIVITY_INFO",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GLOBAL_SEARCH": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GLOBAL_SEARCH",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.GLOBAL_SEARCH_CONTROL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GLOBAL_SEARCH_CONTROL",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.GRANT_RUNTIME_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.GRANT_RUNTIME_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature|installer|verifier"
        },
        "android.permission.HARDWARE_TEST": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.HARDWARE_TEST",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.HDMI_CEC": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.HDMI_CEC",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS",
            "permission_group": "",
            "protection_level": "signature|installer"
        },
        "android.permission.INJECT_EVENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INJECT_EVENTS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.INSTALL_GRANT_RUNTIME_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTALL_GRANT_RUNTIME_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature|installer|verifier"
        },
        "android.permission.INSTALL_LOCATION_PROVIDER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTALL_LOCATION_PROVIDER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.INSTALL_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTALL_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.INSTALL_PACKAGE_UPDATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTALL_PACKAGE_UPDATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.INSTALL_SELF_UPDATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTALL_SELF_UPDATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.INSTANT_APP_FOREGROUND_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INSTANT_APP_FOREGROUND_SERVICE",
            "permission_group": "",
            "protection_level": "signature|development|instant|appop"
        },
        "android.permission.INTENT_FILTER_VERIFICATION_AGENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INTENT_FILTER_VERIFICATION_AGENT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.INTERACT_ACROSS_USERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INTERACT_ACROSS_USERS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.INTERACT_ACROSS_USERS_FULL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INTERACT_ACROSS_USERS_FULL",
            "permission_group": "",
            "protection_level": "signature|installer"
        },
        "android.permission.INTERNAL_DELETE_CACHE_FILES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INTERNAL_DELETE_CACHE_FILES",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.INTERNAL_SYSTEM_WINDOW": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INTERNAL_SYSTEM_WINDOW",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.INTERNET": {
            "description": "Allows the app to create\n         network sockets and use custom network protocols. The browser and other\n         applications provide means to send data to the internet, so this\n         permission is not required to send data to the internet.",
            "description_ptr": "permdesc_createNetworkSockets",
            "label": "have full network access",
            "label_ptr": "permlab_createNetworkSockets",
            "name": "android.permission.INTERNET",
            "permission_group": "",
            "protection_level": "normal|instant"
        },
        "android.permission.INVOKE_CARRIER_SETUP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.INVOKE_CARRIER_SETUP",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.KILL_BACKGROUND_PROCESSES": {
            "description": "Allows the app to end\n            background processes of other apps.    This may cause other apps to stop\n            running.",
            "description_ptr": "permdesc_killBackgroundProcesses",
            "label": "close other apps",
            "label_ptr": "permlab_killBackgroundProcesses",
            "name": "android.permission.KILL_BACKGROUND_PROCESSES",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.KILL_UID": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.KILL_UID",
            "permission_group": "",
            "protection_level": "signature|installer"
        },
        "android.permission.LAUNCH_TRUST_AGENT_SETTINGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.LAUNCH_TRUST_AGENT_SETTINGS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.LOCAL_MAC_ADDRESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.LOCAL_MAC_ADDRESS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.LOCATION_HARDWARE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.LOCATION_HARDWARE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.LOOP_RADIO": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.LOOP_RADIO",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_ACCOUNTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_ACCOUNTS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.MANAGE_ACTIVITY_STACKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_ACTIVITY_STACKS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.MANAGE_APP_OPS_MODES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_APP_OPS_MODES",
            "permission_group": "",
            "protection_level": "signature|installer|verifier"
        },
        "android.permission.MANAGE_APP_OPS_RESTRICTIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_APP_OPS_RESTRICTIONS",
            "permission_group": "",
            "protection_level": "signature|installer"
        },
        "android.permission.MANAGE_APP_TOKENS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_APP_TOKENS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_AUDIO_POLICY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_AUDIO_POLICY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_AUTO_FILL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_AUTO_FILL",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_BIND_INSTANT_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_BIND_INSTANT_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_BLUETOOTH_WHEN_PERMISSION_REVIEW_REQUIRED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_BLUETOOTH_WHEN_PERMISSION_REVIEW_REQUIRED",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_CAMERA": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_CAMERA",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_CARRIER_OEM_UNLOCK_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_CARRIER_OEM_UNLOCK_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_CA_CERTIFICATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_CA_CERTIFICATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_DEVICE_ADMINS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_DEVICE_ADMINS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_DOCUMENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_DOCUMENTS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_FINGERPRINT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_FINGERPRINT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_IPSEC_TUNNELS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_IPSEC_TUNNELS",
            "permission_group": "",
            "protection_level": "signature|appop"
        },
        "android.permission.MANAGE_LOWPAN_INTERFACES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_LOWPAN_INTERFACES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_MEDIA_PROJECTION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_MEDIA_PROJECTION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_NETWORK_POLICY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_NETWORK_POLICY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_NOTIFICATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_NOTIFICATIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_OWN_CALLS": {
            "description": "Allows the app to route its calls through the system in\n                order to improve the calling experience.",
            "description_ptr": "permdesc_manageOwnCalls",
            "label": "route calls through the system",
            "label_ptr": "permlab_manageOwnCalls",
            "name": "android.permission.MANAGE_OWN_CALLS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS": {
            "description": "Allows apps to set the profile owners and the device owner.",
            "description_ptr": "permdesc_manageProfileAndDeviceOwners",
            "label": "manage profile and device owners",
            "label_ptr": "permlab_manageProfileAndDeviceOwners",
            "name": "android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_SCOPED_ACCESS_DIRECTORY_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_SCOPED_ACCESS_DIRECTORY_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_SENSORS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_SENSORS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_SLICE_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_SLICE_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MANAGE_SOUND_TRIGGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_SOUND_TRIGGER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_SUBSCRIPTION_PLANS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_SUBSCRIPTION_PLANS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_USB": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_USB",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_USERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_USERS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_USER_OEM_UNLOCK_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_USER_OEM_UNLOCK_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_VOICE_KEYPHRASES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_VOICE_KEYPHRASES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MANAGE_WIFI_WHEN_PERMISSION_REVIEW_REQUIRED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MANAGE_WIFI_WHEN_PERMISSION_REVIEW_REQUIRED",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MASTER_CLEAR": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MASTER_CLEAR",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MEDIA_CONTENT_CONTROL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MEDIA_CONTENT_CONTROL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_ACCESSIBILITY_DATA": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_ACCESSIBILITY_DATA",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_AUDIO_ROUTING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_AUDIO_ROUTING",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_AUDIO_SETTINGS": {
            "description": "Allows the app to modify global audio settings such as volume and which speaker is used for output.",
            "description_ptr": "permdesc_modifyAudioSettings",
            "label": "change your audio settings",
            "label_ptr": "permlab_modifyAudioSettings",
            "name": "android.permission.MODIFY_AUDIO_SETTINGS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.MODIFY_CELL_BROADCASTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_CELL_BROADCASTS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_DAY_NIGHT_MODE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_DAY_NIGHT_MODE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_NETWORK_ACCOUNTING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_NETWORK_ACCOUNTING",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_PARENTAL_CONTROLS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_PARENTAL_CONTROLS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_PHONE_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_PHONE_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_QUIET_MODE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_QUIET_MODE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MODIFY_THEME_OVERLAY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MODIFY_THEME_OVERLAY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.MOUNT_FORMAT_FILESYSTEMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MOUNT_FORMAT_FILESYSTEMS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.MOVE_PACKAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.MOVE_PACKAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.NETWORK_BYPASS_PRIVATE_DNS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NETWORK_BYPASS_PRIVATE_DNS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.NETWORK_SETTINGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NETWORK_SETTINGS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.NETWORK_SETUP_WIZARD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NETWORK_SETUP_WIZARD",
            "permission_group": "",
            "protection_level": "signature|setup"
        },
        "android.permission.NETWORK_STACK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NETWORK_STACK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.NET_ADMIN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NET_ADMIN",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.NET_TUNNELING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NET_TUNNELING",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.NFC": {
            "description": "Allows the app to communicate\n            with Near Field Communication (NFC) tags, cards, and readers.",
            "description_ptr": "permdesc_nfc",
            "label": "control Near Field Communication",
            "label_ptr": "permlab_nfc",
            "name": "android.permission.NFC",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.NFC_HANDOVER_STATUS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NFC_HANDOVER_STATUS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.NFC_TRANSACTION_EVENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NFC_TRANSACTION_EVENT",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.NOTIFICATION_DURING_SETUP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NOTIFICATION_DURING_SETUP",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.NOTIFY_PENDING_SYSTEM_UPDATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NOTIFY_PENDING_SYSTEM_UPDATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.NOTIFY_TV_INPUTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.NOTIFY_TV_INPUTS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.OBSERVE_APP_USAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.OBSERVE_APP_USAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.OBSERVE_GRANT_REVOKE_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.OBSERVE_GRANT_REVOKE_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.OEM_UNLOCK_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.OEM_UNLOCK_STATE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.OPEN_APPLICATION_DETAILS_OPEN_BY_DEFAULT_PAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.OPEN_APPLICATION_DETAILS_OPEN_BY_DEFAULT_PAGE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.OVERRIDE_WIFI_CONFIG": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.OVERRIDE_WIFI_CONFIG",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PACKAGE_USAGE_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PACKAGE_USAGE_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged|development|appop"
        },
        "android.permission.PACKAGE_VERIFICATION_AGENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PACKAGE_VERIFICATION_AGENT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PACKET_KEEPALIVE_OFFLOAD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PACKET_KEEPALIVE_OFFLOAD",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PEERS_MAC_ADDRESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PEERS_MAC_ADDRESS",
            "permission_group": "",
            "protection_level": "signature|setup"
        },
        "android.permission.PERFORM_CDMA_PROVISIONING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PERFORM_CDMA_PROVISIONING",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PERFORM_SIM_ACTIVATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PERFORM_SIM_ACTIVATION",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PERSISTENT_ACTIVITY": {
            "description": "Allows the app to make parts of itself persistent in memory.    This can limit memory available to other apps slowing down the phone.",
            "description_ptr": "permdesc_persistentActivity",
            "label": "make app always run",
            "label_ptr": "permlab_persistentActivity",
            "name": "android.permission.PERSISTENT_ACTIVITY",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.PROCESS_OUTGOING_CALLS": {
            "description": "Allows the app to see the\n                number being dialed during an outgoing call with the option to redirect\n                the call to a different number or abort the call altogether.",
            "description_ptr": "permdesc_processOutgoingCalls",
            "label": "reroute outgoing calls",
            "label_ptr": "permlab_processOutgoingCalls",
            "name": "android.permission.PROCESS_OUTGOING_CALLS",
            "permission_group": "android.permission-group.CALL_LOG",
            "protection_level": "dangerous"
        },
        "android.permission.PROVIDE_RESOLVER_RANKER_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PROVIDE_RESOLVER_RANKER_SERVICE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.PROVIDE_TRUST_AGENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.PROVIDE_TRUST_AGENT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.QUERY_DO_NOT_ASK_CREDENTIALS_ON_BOOT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.QUERY_DO_NOT_ASK_CREDENTIALS_ON_BOOT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.QUERY_TIME_ZONE_RULES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.QUERY_TIME_ZONE_RULES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_BLOCKED_NUMBERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_BLOCKED_NUMBERS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.READ_CALENDAR": {
            "description": "This app can read all calendar events stored on your phone and share or save your calendar data.",
            "description_ptr": "permdesc_readCalendar",
            "label": "Read calendar events and details",
            "label_ptr": "permlab_readCalendar",
            "name": "android.permission.READ_CALENDAR",
            "permission_group": "android.permission-group.CALENDAR",
            "protection_level": "dangerous"
        },
        "android.permission.READ_CALL_LOG": {
            "description": "This app can read your call history.",
            "description_ptr": "permdesc_readCallLog",
            "label": "read call log",
            "label_ptr": "permlab_readCallLog",
            "name": "android.permission.READ_CALL_LOG",
            "permission_group": "android.permission-group.CALL_LOG",
            "protection_level": "dangerous"
        },
        "android.permission.READ_CELL_BROADCASTS": {
            "description": "Allows the app to read\n                cell broadcast messages received by your device. Cell broadcast alerts\n                are delivered in some locations to warn you of emergency situations.\n                Malicious apps may interfere with the performance or operation of your\n                device when an emergency cell broadcast is received.",
            "description_ptr": "permdesc_readCellBroadcasts",
            "label": "read cell broadcast messages",
            "label_ptr": "permlab_readCellBroadcasts",
            "name": "android.permission.READ_CELL_BROADCASTS",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.READ_CONTACTS": {
            "description": "Allows the app to\n            read data about your contacts stored on your phone, including the\n            frequency with which you've called, emailed, or communicated in other ways\n            with specific individuals. This permission allows apps to save your\n            contact data, and malicious apps may share contact data without your\n            knowledge.",
            "description_ptr": "permdesc_readContacts",
            "label": "read your contacts",
            "label_ptr": "permlab_readContacts",
            "name": "android.permission.READ_CONTACTS",
            "permission_group": "android.permission-group.CONTACTS",
            "protection_level": "dangerous"
        },
        "android.permission.READ_CONTENT_RATING_SYSTEMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_CONTENT_RATING_SYSTEMS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_DREAM_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_DREAM_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "description": "Allows the app to read the contents of your SD card.",
            "description_ptr": "permdesc_sdcardRead",
            "label": "read the contents of your SD card",
            "label_ptr": "permlab_sdcardRead",
            "name": "android.permission.READ_EXTERNAL_STORAGE",
            "permission_group": "android.permission-group.STORAGE",
            "protection_level": "dangerous"
        },
        "android.permission.READ_FRAME_BUFFER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_FRAME_BUFFER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_INPUT_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_INPUT_STATE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.READ_INSTALL_SESSIONS": {
            "description": "Allows an application to read install sessions. This allows it to see details about active package installations.",
            "description_ptr": "permdesc_readInstallSessions",
            "label": "read install sessions",
            "label_ptr": "permlab_readInstallSessions",
            "name": "android.permission.READ_INSTALL_SESSIONS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_LOGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_LOGS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.READ_LOWPAN_CREDENTIAL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_LOWPAN_CREDENTIAL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_NETWORK_USAGE_HISTORY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_NETWORK_USAGE_HISTORY",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_OEM_UNLOCK_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_OEM_UNLOCK_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_PHONE_NUMBERS": {
            "description": "Allows the app to access the phone numbers of the device.",
            "description_ptr": "permdesc_readPhoneNumbers",
            "label": "read phone numbers",
            "label_ptr": "permlab_readPhoneNumbers",
            "name": "android.permission.READ_PHONE_NUMBERS",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous|instant"
        },
        "android.permission.READ_PHONE_STATE": {
            "description": "Allows the app to access the phone\n            features of the device.    This permission allows the app to determine the\n            phone number and device IDs, whether a call is active, and the remote number\n            connected by a call.",
            "description_ptr": "permdesc_readPhoneState",
            "label": "read phone status and identity",
            "label_ptr": "permlab_readPhoneState",
            "name": "android.permission.READ_PHONE_STATE",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous"
        },
        "android.permission.READ_PRECISE_PHONE_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_PRECISE_PHONE_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_PRINT_SERVICES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_PRINT_SERVICES",
            "permission_group": "",
            "protection_level": "signature|preinstalled"
        },
        "android.permission.READ_PRINT_SERVICE_RECOMMENDATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_PRINT_SERVICE_RECOMMENDATIONS",
            "permission_group": "",
            "protection_level": "signature|preinstalled"
        },
        "android.permission.READ_PRIVILEGED_PHONE_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_PRIVILEGED_PHONE_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_PROFILE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_PROFILE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_RUNTIME_PROFILES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_RUNTIME_PROFILES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_SEARCH_INDEXABLES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_SEARCH_INDEXABLES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_SMS": {
            "description": "This app can read all SMS (text) messages stored on your phone.",
            "description_ptr": "permdesc_readSms",
            "label": "read your text messages (SMS or MMS)",
            "label_ptr": "permlab_readSms",
            "name": "android.permission.READ_SMS",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.READ_SOCIAL_STREAM": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_SOCIAL_STREAM",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_SYNC_SETTINGS": {
            "description": "Allows the app to read the sync settings for an account. For example, this can determine whether the People app is synced with an account.",
            "description_ptr": "permdesc_readSyncSettings",
            "label": "read sync settings",
            "label_ptr": "permlab_readSyncSettings",
            "name": "android.permission.READ_SYNC_SETTINGS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_SYNC_STATS": {
            "description": "Allows an app to read the sync stats for an account, including the history of sync events and how much data is synced. ",
            "description_ptr": "permdesc_readSyncStats",
            "label": "read sync statistics",
            "label_ptr": "permlab_readSyncStats",
            "name": "android.permission.READ_SYNC_STATS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_SYSTEM_UPDATE_INFO": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_SYSTEM_UPDATE_INFO",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.READ_USER_DICTIONARY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_USER_DICTIONARY",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.READ_WALLPAPER_INTERNAL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_WALLPAPER_INTERNAL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.READ_WIFI_CREDENTIAL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.READ_WIFI_CREDENTIAL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REAL_GET_TASKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REAL_GET_TASKS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REBOOT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REBOOT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_BLUETOOTH_MAP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_BLUETOOTH_MAP",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_BOOT_COMPLETED": {
            "description": "Allows the app to\n                have itself started as soon as the system has finished booting.\n                This can make it take longer to start the phone and allow the\n                app to slow down the overall phone by always running.",
            "description_ptr": "permdesc_receiveBootCompleted",
            "label": "run at startup",
            "label_ptr": "permlab_receiveBootCompleted",
            "name": "android.permission.RECEIVE_BOOT_COMPLETED",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.RECEIVE_DATA_ACTIVITY_CHANGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_DATA_ACTIVITY_CHANGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_EMERGENCY_BROADCAST": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_EMERGENCY_BROADCAST",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_MEDIA_RESOURCE_USAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_MEDIA_RESOURCE_USAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_MMS": {
            "description": "Allows the app to receive and process MMS\n            messages. This means the app could monitor or delete messages sent to your\n            device without showing them to you.",
            "description_ptr": "permdesc_receiveMms",
            "label": "receive text messages (MMS)",
            "label_ptr": "permlab_receiveMms",
            "name": "android.permission.RECEIVE_MMS",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.RECEIVE_SMS": {
            "description": "Allows the app to receive and process SMS\n            messages. This means the app could monitor or delete messages sent to your\n            device without showing them to you.",
            "description_ptr": "permdesc_receiveSms",
            "label": "receive text messages (SMS)",
            "label_ptr": "permlab_receiveSms",
            "name": "android.permission.RECEIVE_SMS",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.RECEIVE_STK_COMMANDS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_STK_COMMANDS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECEIVE_WAP_PUSH": {
            "description": "Allows the app to receive and process\n         WAP messages.    This permission includes the ability to monitor or delete\n         messages sent to you without showing them to you.",
            "description_ptr": "permdesc_receiveWapPush",
            "label": "receive text messages (WAP)",
            "label_ptr": "permlab_receiveWapPush",
            "name": "android.permission.RECEIVE_WAP_PUSH",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.RECEIVE_WIFI_CREDENTIAL_CHANGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECEIVE_WIFI_CREDENTIAL_CHANGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECORD_AUDIO": {
            "description": "This app can record audio using the microphone at any time.",
            "description_ptr": "permdesc_recordAudio",
            "label": "record audio",
            "label_ptr": "permlab_recordAudio",
            "name": "android.permission.RECORD_AUDIO",
            "permission_group": "android.permission-group.MICROPHONE",
            "protection_level": "dangerous|instant"
        },
        "android.permission.RECOVERY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECOVERY",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RECOVER_KEYSTORE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RECOVER_KEYSTORE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REGISTER_CALL_PROVIDER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REGISTER_CALL_PROVIDER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REGISTER_CONNECTION_MANAGER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REGISTER_CONNECTION_MANAGER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REGISTER_SIM_SUBSCRIPTION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REGISTER_SIM_SUBSCRIPTION",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REGISTER_WINDOW_MANAGER_LISTENERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REGISTER_WINDOW_MANAGER_LISTENERS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.REMOTE_AUDIO_PLAYBACK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REMOTE_AUDIO_PLAYBACK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.REMOVE_DRM_CERTIFICATES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REMOVE_DRM_CERTIFICATES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.REMOVE_TASKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REMOVE_TASKS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.REORDER_TASKS": {
            "description": "Allows the app to move tasks to the\n            foreground and background.    The app may do this without your input.",
            "description_ptr": "permdesc_reorderTasks",
            "label": "reorder running apps",
            "label_ptr": "permlab_reorderTasks",
            "name": "android.permission.REORDER_TASKS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND": {
            "description": "This app can run in the background. This may drain battery faster.",
            "description_ptr": "permdesc_runInBackground",
            "label": "run in the background",
            "label_ptr": "permlab_runInBackground",
            "name": "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": {
            "description": "This app can use data in the background. This may increase data usage.",
            "description_ptr": "permdesc_useDataInBackground",
            "label": "use data in the background",
            "label_ptr": "permlab_useDataInBackground",
            "name": "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.REQUEST_DELETE_PACKAGES": {
            "description": "Allows an application to request deletion of packages.",
            "description_ptr": "permdesc_requestDeletePackages",
            "label": "request delete packages",
            "label_ptr": "permlab_requestDeletePackages",
            "name": "android.permission.REQUEST_DELETE_PACKAGES",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
            "description": "Allows an app to ask for permission to ignore battery optimizations for that app.",
            "description_ptr": "permdesc_requestIgnoreBatteryOptimizations",
            "label": "ask to ignore battery optimizations",
            "label_ptr": "permlab_requestIgnoreBatteryOptimizations",
            "name": "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.REQUEST_INSTALL_PACKAGES": {
            "description": "Allows an application to request installation of packages.",
            "description_ptr": "permdesc_requestInstallPackages",
            "label": "request install packages",
            "label_ptr": "permlab_requestInstallPackages",
            "name": "android.permission.REQUEST_INSTALL_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|appop"
        },
        "android.permission.REQUEST_NETWORK_SCORES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REQUEST_NETWORK_SCORES",
            "permission_group": "",
            "protection_level": "signature|setup"
        },
        "android.permission.RESET_FINGERPRINT_LOCKOUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RESET_FINGERPRINT_LOCKOUT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.RESET_SHORTCUT_MANAGER_THROTTLING": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RESET_SHORTCUT_MANAGER_THROTTLING",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.RESTART_PACKAGES": {
            "description": "Allows the app to end\n            background processes of other apps.    This may cause other apps to stop\n            running.",
            "description_ptr": "permdesc_killBackgroundProcesses",
            "label": "close other apps",
            "label_ptr": "permlab_killBackgroundProcesses",
            "name": "android.permission.RESTART_PACKAGES",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.RESTRICTED_VR_ACCESS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RESTRICTED_VR_ACCESS",
            "permission_group": "",
            "protection_level": "signature|preinstalled"
        },
        "android.permission.RETRIEVE_WINDOW_CONTENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RETRIEVE_WINDOW_CONTENT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.RETRIEVE_WINDOW_TOKEN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.RETRIEVE_WINDOW_TOKEN",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.REVOKE_RUNTIME_PERMISSIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.REVOKE_RUNTIME_PERMISSIONS",
            "permission_group": "",
            "protection_level": "signature|installer|verifier"
        },
        "android.permission.RUN_IN_BACKGROUND": {
            "description": "This app can run in the background. This may drain battery faster.",
            "description_ptr": "permdesc_runInBackground",
            "label": "run in the background",
            "label_ptr": "permlab_runInBackground",
            "name": "android.permission.RUN_IN_BACKGROUND",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SCORE_NETWORKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SCORE_NETWORKS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SEND_EMBMS_INTENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SEND_EMBMS_INTENTS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SEND_RESPOND_VIA_MESSAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SEND_RESPOND_VIA_MESSAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SEND_SHOW_SUSPENDED_APP_DETAILS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SEND_SHOW_SUSPENDED_APP_DETAILS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SEND_SMS": {
            "description": "Allows the app to send SMS messages.\n         This may result in unexpected charges. Malicious apps may cost you money by\n         sending messages without your confirmation.",
            "description_ptr": "permdesc_sendSms",
            "label": "send and view SMS messages",
            "label_ptr": "permlab_sendSms",
            "name": "android.permission.SEND_SMS",
            "permission_group": "android.permission-group.SMS",
            "protection_level": "dangerous"
        },
        "android.permission.SEND_SMS_NO_CONFIRMATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SEND_SMS_NO_CONFIRMATION",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SERIAL_PORT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SERIAL_PORT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SET_ACTIVITY_WATCHER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_ACTIVITY_WATCHER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_ALWAYS_FINISH": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_ALWAYS_FINISH",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_ANIMATION_SCALE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_ANIMATION_SCALE",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_DEBUG_APP": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_DEBUG_APP",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_DISPLAY_OFFSET": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_DISPLAY_OFFSET",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SET_HARMFUL_APP_WARNINGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_HARMFUL_APP_WARNINGS",
            "permission_group": "",
            "protection_level": "signature|verifier"
        },
        "android.permission.SET_INPUT_CALIBRATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_INPUT_CALIBRATION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_KEYBOARD_LAYOUT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_KEYBOARD_LAYOUT",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_MEDIA_KEY_LISTENER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_MEDIA_KEY_LISTENER",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_ORIENTATION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_ORIENTATION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_POINTER_SPEED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_POINTER_SPEED",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_PREFERRED_APPLICATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_PREFERRED_APPLICATIONS",
            "permission_group": "",
            "protection_level": "signature|verifier"
        },
        "android.permission.SET_PROCESS_LIMIT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_PROCESS_LIMIT",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_SCREEN_COMPATIBILITY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_SCREEN_COMPATIBILITY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SET_TIME": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_TIME",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SET_TIME_ZONE": {
            "description": "Allows the app to change the phone's time zone.",
            "description_ptr": "permdesc_setTimeZone",
            "label": "set time zone",
            "label_ptr": "permlab_setTimeZone",
            "name": "android.permission.SET_TIME_ZONE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SET_VOLUME_KEY_LONG_PRESS_LISTENER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_VOLUME_KEY_LONG_PRESS_LISTENER",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.SET_WALLPAPER": {
            "description": "Allows the app to set the system wallpaper.",
            "description_ptr": "permdesc_setWallpaper",
            "label": "set wallpaper",
            "label_ptr": "permlab_setWallpaper",
            "name": "android.permission.SET_WALLPAPER",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.SET_WALLPAPER_COMPONENT": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SET_WALLPAPER_COMPONENT",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SET_WALLPAPER_HINTS": {
            "description": "Allows the app to set the system wallpaper size hints.",
            "description_ptr": "permdesc_setWallpaperHints",
            "label": "adjust your wallpaper size",
            "label_ptr": "permlab_setWallpaperHints",
            "name": "android.permission.SET_WALLPAPER_HINTS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.SHOW_KEYGUARD_MESSAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SHOW_KEYGUARD_MESSAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SHUTDOWN": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SHUTDOWN",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SIGNAL_PERSISTENT_PROCESSES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SIGNAL_PERSISTENT_PROCESSES",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.START_ANY_ACTIVITY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.START_ANY_ACTIVITY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.START_TASKS_FROM_RECENTS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.START_TASKS_FROM_RECENTS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.STATSCOMPANION": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.STATSCOMPANION",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.STATUS_BAR": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.STATUS_BAR",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.STATUS_BAR_SERVICE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.STATUS_BAR_SERVICE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.STOP_APP_SWITCHES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.STOP_APP_SWITCHES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.STORAGE_INTERNAL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.STORAGE_INTERNAL",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.SUBSCRIBED_FEEDS_READ": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SUBSCRIBED_FEEDS_READ",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.SUBSCRIBED_FEEDS_WRITE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SUBSCRIBED_FEEDS_WRITE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.SUBSTITUTE_NOTIFICATION_APP_NAME": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SUBSTITUTE_NOTIFICATION_APP_NAME",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SUSPEND_APPS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.SUSPEND_APPS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "description": "This app can appear on top of other apps or other parts of the screen. This may interfere with normal app usage and change the way that other apps appear.",
            "description_ptr": "permdesc_systemAlertWindow",
            "label": "This app can appear on top of other apps",
            "label_ptr": "permlab_systemAlertWindow",
            "name": "android.permission.SYSTEM_ALERT_WINDOW",
            "permission_group": "",
            "protection_level": "signature|preinstalled|appop|pre23|development"
        },
        "android.permission.TABLET_MODE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TABLET_MODE",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.TEMPORARY_ENABLE_ACCESSIBILITY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TEMPORARY_ENABLE_ACCESSIBILITY",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.TEST_BLACKLISTED_PASSWORD": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TEST_BLACKLISTED_PASSWORD",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.TETHER_PRIVILEGED": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TETHER_PRIVILEGED",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.TRANSMIT_IR": {
            "description": "Allows the app to use the phone's infrared transmitter.",
            "description_ptr": "permdesc_transmitIr",
            "label": "transmit infrared",
            "label_ptr": "permlab_transmitIr",
            "name": "android.permission.TRANSMIT_IR",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.TRIGGER_TIME_ZONE_RULES_CHECK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TRIGGER_TIME_ZONE_RULES_CHECK",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.TRUST_LISTENER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TRUST_LISTENER",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.TV_INPUT_HARDWARE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TV_INPUT_HARDWARE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.TV_VIRTUAL_REMOTE_CONTROLLER": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.TV_VIRTUAL_REMOTE_CONTROLLER",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.UNLIMITED_SHORTCUTS_API_CALLS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UNLIMITED_SHORTCUTS_API_CALLS",
            "permission_group": "",
            "protection_level": "signature|textClassifier"
        },
        "android.permission.UPDATE_APP_OPS_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_APP_OPS_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged|installer"
        },
        "android.permission.UPDATE_CONFIG": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_CONFIG",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.UPDATE_DEVICE_STATS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_DEVICE_STATS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.UPDATE_LOCK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_LOCK",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.UPDATE_LOCK_TASK_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_LOCK_TASK_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|setup"
        },
        "android.permission.UPDATE_TIME_ZONE_RULES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.UPDATE_TIME_ZONE_RULES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.USER_ACTIVITY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.USER_ACTIVITY",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.USE_BIOMETRIC": {
            "description": "Allows the app to use biometric hardware for authentication",
            "description_ptr": "permdesc_useBiometric",
            "label": "use biometric hardware",
            "label_ptr": "permlab_useBiometric",
            "name": "android.permission.USE_BIOMETRIC",
            "permission_group": "android.permission-group.SENSORS",
            "protection_level": "normal"
        },
        "android.permission.USE_COLORIZED_NOTIFICATIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.USE_COLORIZED_NOTIFICATIONS",
            "permission_group": "",
            "protection_level": "signature|setup"
        },
        "android.permission.USE_CREDENTIALS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.USE_CREDENTIALS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.USE_DATA_IN_BACKGROUND": {
            "description": "This app can use data in the background. This may increase data usage.",
            "description_ptr": "permdesc_useDataInBackground",
            "label": "use data in the background",
            "label_ptr": "permlab_useDataInBackground",
            "name": "android.permission.USE_DATA_IN_BACKGROUND",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.USE_FINGERPRINT": {
            "description": "Allows the app to use fingerprint hardware for authentication",
            "description_ptr": "permdesc_useFingerprint",
            "label": "use fingerprint hardware",
            "label_ptr": "permlab_useFingerprint",
            "name": "android.permission.USE_FINGERPRINT",
            "permission_group": "android.permission-group.SENSORS",
            "protection_level": "normal"
        },
        "android.permission.USE_RESERVED_DISK": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.USE_RESERVED_DISK",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.USE_SIP": {
            "description": "Allows the app to make and receive SIP calls.",
            "description_ptr": "permdesc_use_sip",
            "label": "make/receive SIP calls",
            "label_ptr": "permlab_use_sip",
            "name": "android.permission.USE_SIP",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous"
        },
        "android.permission.VIBRATE": {
            "description": "Allows the app to control the vibrator.",
            "description_ptr": "permdesc_vibrate",
            "label": "control vibration",
            "label_ptr": "permlab_vibrate",
            "name": "android.permission.VIBRATE",
            "permission_group": "",
            "protection_level": "normal|instant"
        },
        "android.permission.VIEW_INSTANT_APPS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.VIEW_INSTANT_APPS",
            "permission_group": "",
            "protection_level": "signature|preinstalled"
        },
        "android.permission.WAKE_LOCK": {
            "description": "Allows the app to prevent the phone from going to sleep.",
            "description_ptr": "permdesc_wakeLock",
            "label": "prevent phone from sleeping",
            "label_ptr": "permlab_wakeLock",
            "name": "android.permission.WAKE_LOCK",
            "permission_group": "",
            "protection_level": "normal|instant"
        },
        "android.permission.WATCH_APPOPS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WATCH_APPOPS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.WRITE_APN_SETTINGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_APN_SETTINGS",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.WRITE_BLOCKED_NUMBERS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_BLOCKED_NUMBERS",
            "permission_group": "",
            "protection_level": "signature"
        },
        "android.permission.WRITE_CALENDAR": {
            "description": "This app can add, remove, or change calendar events on your phone. This app can send messages that may appear to come from calendar owners, or change events without notifying their owners.",
            "description_ptr": "permdesc_writeCalendar",
            "label": "add or modify calendar events and send email to guests without owners' knowledge",
            "label_ptr": "permlab_writeCalendar",
            "name": "android.permission.WRITE_CALENDAR",
            "permission_group": "android.permission-group.CALENDAR",
            "protection_level": "dangerous"
        },
        "android.permission.WRITE_CALL_LOG": {
            "description": "Allows the app to modify your phone's call log, including data about incoming and outgoing calls.\n                Malicious apps may use this to erase or modify your call log.",
            "description_ptr": "permdesc_writeCallLog",
            "label": "write call log",
            "label_ptr": "permlab_writeCallLog",
            "name": "android.permission.WRITE_CALL_LOG",
            "permission_group": "android.permission-group.CALL_LOG",
            "protection_level": "dangerous"
        },
        "android.permission.WRITE_CONTACTS": {
            "description": "Allows the app to\n        modify the data about your contacts stored on your phone, including the\n        frequency with which you've called, emailed, or communicated in other ways\n        with specific contacts. This permission allows apps to delete contact\n        data.",
            "description_ptr": "permdesc_writeContacts",
            "label": "modify your contacts",
            "label_ptr": "permlab_writeContacts",
            "name": "android.permission.WRITE_CONTACTS",
            "permission_group": "android.permission-group.CONTACTS",
            "protection_level": "dangerous"
        },
        "android.permission.WRITE_DREAM_STATE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_DREAM_STATE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.WRITE_EMBEDDED_SUBSCRIPTIONS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_EMBEDDED_SUBSCRIPTIONS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "description": "Allows the app to write to the SD card.",
            "description_ptr": "permdesc_sdcardWrite",
            "label": "modify or delete the contents of your SD card",
            "label_ptr": "permlab_sdcardWrite",
            "name": "android.permission.WRITE_EXTERNAL_STORAGE",
            "permission_group": "android.permission-group.STORAGE",
            "protection_level": "dangerous"
        },
        "android.permission.WRITE_GSERVICES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_GSERVICES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.WRITE_MEDIA_STORAGE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_MEDIA_STORAGE",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "android.permission.WRITE_PROFILE": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_PROFILE",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.WRITE_SECURE_SETTINGS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_SECURE_SETTINGS",
            "permission_group": "",
            "protection_level": "signature|privileged|development"
        },
        "android.permission.WRITE_SETTINGS": {
            "description": "Allows the app to modify the\n                system's settings data. Malicious apps may corrupt your system's\n                configuration.",
            "description_ptr": "permdesc_writeSettings",
            "label": "modify system settings",
            "label_ptr": "permlab_writeSettings",
            "name": "android.permission.WRITE_SETTINGS",
            "permission_group": "",
            "protection_level": "signature|preinstalled|appop|pre23"
        },
        "android.permission.WRITE_SMS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_SMS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.WRITE_SOCIAL_STREAM": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_SOCIAL_STREAM",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.WRITE_SYNC_SETTINGS": {
            "description": "Allows an app to modify the sync settings for an account.    For example, this can be used to enable sync of the People app with an account.",
            "description_ptr": "permdesc_writeSyncSettings",
            "label": "toggle sync on and off",
            "label_ptr": "permlab_writeSyncSettings",
            "name": "android.permission.WRITE_SYNC_SETTINGS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "android.permission.WRITE_USER_DICTIONARY": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "android.permission.WRITE_USER_DICTIONARY",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.alarm.permission.SET_ALARM": {
            "description": "Allows the app to set an alarm in\n                an installed alarm clock app. Some alarm clock apps may\n                not implement this feature.",
            "description_ptr": "permdesc_setAlarm",
            "label": "set an alarm",
            "label_ptr": "permlab_setAlarm",
            "name": "com.android.alarm.permission.SET_ALARM",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.browser.permission.READ_HISTORY_BOOKMARKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "com.android.browser.permission.READ_HISTORY_BOOKMARKS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.launcher.permission.INSTALL_SHORTCUT": {
            "description": "Allows an application to add\n                Homescreen shortcuts without user intervention.",
            "description_ptr": "permdesc_install_shortcut",
            "label": "install shortcuts",
            "label_ptr": "permlab_install_shortcut",
            "name": "com.android.launcher.permission.INSTALL_SHORTCUT",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.launcher.permission.UNINSTALL_SHORTCUT": {
            "description": "Allows the application to remove\n                Homescreen shortcuts without user intervention.",
            "description_ptr": "permdesc_uninstall_shortcut",
            "label": "uninstall shortcuts",
            "label_ptr": "permlab_uninstall_shortcut",
            "name": "com.android.launcher.permission.UNINSTALL_SHORTCUT",
            "permission_group": "",
            "protection_level": "normal"
        },
        "com.android.permission.INSTALL_EXISTING_PACKAGES": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "com.android.permission.INSTALL_EXISTING_PACKAGES",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "com.android.voicemail.permission.ADD_VOICEMAIL": {
            "description": "Allows the app to add messages\n            to your voicemail inbox.",
            "description_ptr": "permdesc_addVoicemail",
            "label": "add voicemail",
            "label_ptr": "permlab_addVoicemail",
            "name": "com.android.voicemail.permission.ADD_VOICEMAIL",
            "permission_group": "android.permission-group.PHONE",
            "protection_level": "dangerous"
        },
        "com.android.voicemail.permission.READ_VOICEMAIL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "com.android.voicemail.permission.READ_VOICEMAIL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        },
        "com.android.voicemail.permission.WRITE_VOICEMAIL": {
            "description": "",
            "description_ptr": "",
            "label": "",
            "label_ptr": "",
            "name": "com.android.voicemail.permission.WRITE_VOICEMAIL",
            "permission_group": "",
            "protection_level": "signature|privileged"
        }
    }
}