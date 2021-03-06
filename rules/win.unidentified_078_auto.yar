rule win_unidentified_078_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.unidentified_078."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_078"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { e9???????? 80fa0c 0f8412010000 0f8cee000000 80fa0d 0f8421010000 }
            // n = 6, score = 200
            //   e9????????           |                     
            //   80fa0c               | dec                 ecx
            //   0f8412010000         | shl                 ecx, cl
            //   0f8cee000000         | dec                 eax
            //   80fa0d               | shr                 edx, 6
            //   0f8421010000         | dec                 eax

        $sequence_1 = { e8???????? 84c0 750e e8???????? 31d2 89c1 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   84c0                 | lea                 ebx, [edx + ecx*8]
            //   750e                 | je                  0x1d36
            //   e8????????           |                     
            //   31d2                 | dec                 ecx
            //   89c1                 | dec                 ecx
            //   e8????????           |                     

        $sequence_2 = { 5b 5e e9???????? ebc0 ebbe ebbc ebba }
            // n = 7, score = 200
            //   5b                   | cmp                 ecx, 8
            //   5e                   | dec                 eax
            //   e9????????           |                     
            //   ebc0                 | lea                 eax, [0x20ebc]
            //   ebbe                 | dec                 eax
            //   ebbc                 | dec                 eax
            //   ebba                 | lea                 eax, [0x20cfe]

        $sequence_3 = { 0fbed2 e8???????? 0fbed3 ebb3 }
            // n = 4, score = 200
            //   0fbed2               | movzx               ecx, cl
            //   e8????????           |                     
            //   0fbed3               | dec                 esp
            //   ebb3                 | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_4 = { 7437 89da 83e2fd 83fa10 742d }
            // n = 5, score = 200
            //   7437                 | lea                 ecx, [0x243f2]
            //   89da                 | call                ebp
            //   83e2fd               | dec                 eax
            //   83fa10               | lea                 ecx, [0x1e699]
            //   742d                 | mov                 edx, 0x30

        $sequence_5 = { 80fa0c 0f8412010000 0f8cee000000 80fa0d 0f8421010000 80fa1b 0f8576010000 }
            // n = 7, score = 200
            //   80fa0c               | mov                 edx, edi
            //   0f8412010000         | dec                 eax
            //   0f8cee000000         | inc                 ebx
            //   80fa0d               | dec                 eax
            //   0f8421010000         | test                esi, esi
            //   80fa1b               | je                  0x91
            //   0f8576010000         | dec                 eax

        $sequence_6 = { 0f94c1 80fa2f 0f94c2 08d1 }
            // n = 4, score = 200
            //   0f94c1               | jge                 0x1f4
            //   80fa2f               | inc                 esp
            //   0f94c2               | mov                 ah, byte ptr [ebx + ecx]
            //   08d1                 | inc                 ebp

        $sequence_7 = { 7514 8a542e10 80fa5c 0f94c1 }
            // n = 4, score = 200
            //   7514                 | sub                 esp, 0x28
            //   8a542e10             | mov                 al, byte ptr [edx]
            //   80fa5c               | push                ebx
            //   0f94c1               | dec                 eax

        $sequence_8 = { 0f8483000000 3c1c 740d 3c16 0f855a020000 }
            // n = 5, score = 200
            //   0f8483000000         | dec                 eax
            //   3c1c                 | lea                 ecx, [esi + 8]
            //   740d                 | xor                 edx, edx
            //   3c16                 | dec                 eax
            //   0f855a020000         | lea                 ecx, [esi + 0x18]

        $sequence_9 = { 8a44010f 3c5c 7419 3c2f 7415 }
            // n = 5, score = 200
            //   8a44010f             | dec                 ebp
            //   3c5c                 | and                 eax, ecx
            //   7419                 | dec                 edx
            //   3c2f                 | mov                 eax, dword ptr [ecx + eax*8]
            //   7415                 | dec                 eax

    condition:
        7 of them and filesize < 688128
}