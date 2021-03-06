rule win_fatal_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.fatal_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fatal_rat"
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
        $sequence_0 = { 8b06 5f 5e c3 55 8bec }
            // n = 6, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_1 = { c6857dfeffff78 c6857efeffff65 889d7ffeffff c68534ffffff61 c68535ffffff76 c68536ffffff67 }
            // n = 6, score = 100
            //   c6857dfeffff78       | mov                 byte ptr [ebp - 0x183], 0x78
            //   c6857efeffff65       | mov                 byte ptr [ebp - 0x182], 0x65
            //   889d7ffeffff         | mov                 byte ptr [ebp - 0x181], bl
            //   c68534ffffff61       | mov                 byte ptr [ebp - 0xcc], 0x61
            //   c68535ffffff76       | mov                 byte ptr [ebp - 0xcb], 0x76
            //   c68536ffffff67       | mov                 byte ptr [ebp - 0xca], 0x67

        $sequence_2 = { 894608 ffd7 68???????? 894628 ff7608 ffd7 68???????? }
            // n = 7, score = 100
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   894628               | mov                 dword ptr [esi + 0x28], eax
            //   ff7608               | push                dword ptr [esi + 8]
            //   ffd7                 | call                edi
            //   68????????           |                     

        $sequence_3 = { 3bd0 7502 8bf8 48 ebdf 2bf9 57 }
            // n = 7, score = 100
            //   3bd0                 | cmp                 edx, eax
            //   7502                 | jne                 4
            //   8bf8                 | mov                 edi, eax
            //   48                   | dec                 eax
            //   ebdf                 | jmp                 0xffffffe1
            //   2bf9                 | sub                 edi, ecx
            //   57                   | push                edi

        $sequence_4 = { 33ff 57 57 57 57 68???????? eb81 }
            // n = 7, score = 100
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   68????????           |                     
            //   eb81                 | jmp                 0xffffff83

        $sequence_5 = { 75f7 5e 8bc7 5f 5d c3 55 }
            // n = 7, score = 100
            //   75f7                 | jne                 0xfffffff9
            //   5e                   | pop                 esi
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_6 = { 6685c0 741f 83ffff 7e1a 83fe40 7e15 83fe5d }
            // n = 7, score = 100
            //   6685c0               | test                ax, ax
            //   741f                 | je                  0x21
            //   83ffff               | cmp                 edi, -1
            //   7e1a                 | jle                 0x1c
            //   83fe40               | cmp                 esi, 0x40
            //   7e15                 | jle                 0x17
            //   83fe5d               | cmp                 esi, 0x5d

        $sequence_7 = { 83f86a 8bf1 0f8f71010000 83f865 0f8d82010000 }
            // n = 5, score = 100
            //   83f86a               | cmp                 eax, 0x6a
            //   8bf1                 | mov                 esi, ecx
            //   0f8f71010000         | jg                  0x177
            //   83f865               | cmp                 eax, 0x65
            //   0f8d82010000         | jge                 0x188

        $sequence_8 = { 894610 894614 894618 894620 88462c 88462d 89463c }
            // n = 7, score = 100
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   894618               | mov                 dword ptr [esi + 0x18], eax
            //   894620               | mov                 dword ptr [esi + 0x20], eax
            //   88462c               | mov                 byte ptr [esi + 0x2c], al
            //   88462d               | mov                 byte ptr [esi + 0x2d], al
            //   89463c               | mov                 dword ptr [esi + 0x3c], eax

        $sequence_9 = { 57 e8???????? 59 8bf0 56 53 893e }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   53                   | push                ebx
            //   893e                 | mov                 dword ptr [esi], edi

    condition:
        7 of them and filesize < 344064
}