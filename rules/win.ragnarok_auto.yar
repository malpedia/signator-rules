rule win_ragnarok_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ragnarok."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ragnarok"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { c1e908 0fb6c9 0fb689104b4300 314d10 8b4d10 }
            // n = 5, score = 200
            //   c1e908               | shr                 ecx, 8
            //   0fb6c9               | movzx               ecx, cl
            //   0fb689104b4300       | movzx               ecx, byte ptr [ecx + 0x434b10]
            //   314d10               | xor                 dword ptr [ebp + 0x10], ecx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

        $sequence_1 = { 5e 5d c3 ff7508 6a00 }
            // n = 5, score = 200
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0

        $sequence_2 = { 8d4308 57 33ff 894304 897510 85f6 743a }
            // n = 7, score = 200
            //   8d4308               | lea                 eax, dword ptr [ebx + 8]
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   897510               | mov                 dword ptr [ebp + 0x10], esi
            //   85f6                 | test                esi, esi
            //   743a                 | je                  0x3c

        $sequence_3 = { 7429 837dec00 7523 837de804 7618 6a03 68???????? }
            // n = 7, score = 200
            //   7429                 | je                  0x2b
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
            //   7523                 | jne                 0x25
            //   837de804             | cmp                 dword ptr [ebp - 0x18], 4
            //   7618                 | jbe                 0x1a
            //   6a03                 | push                3
            //   68????????           |                     

        $sequence_4 = { 238d54fdffff 338d44fdffff 03d9 8b8d78fdffff 13f8 8b8538fdffff 031cc560af4200 }
            // n = 7, score = 200
            //   238d54fdffff         | and                 ecx, dword ptr [ebp - 0x2ac]
            //   338d44fdffff         | xor                 ecx, dword ptr [ebp - 0x2bc]
            //   03d9                 | add                 ebx, ecx
            //   8b8d78fdffff         | mov                 ecx, dword ptr [ebp - 0x288]
            //   13f8                 | adc                 edi, eax
            //   8b8538fdffff         | mov                 eax, dword ptr [ebp - 0x2c8]
            //   031cc560af4200       | add                 ebx, dword ptr [eax*8 + 0x42af60]

        $sequence_5 = { e8???????? 8bf8 83c420 85ff 0f8484000000 6800020000 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c420               | add                 esp, 0x20
            //   85ff                 | test                edi, edi
            //   0f8484000000         | je                  0x8a
            //   6800020000           | push                0x200
            //   e8????????           |                     

        $sequence_6 = { 03b090c14200 03b40514ffffff 03f7 8bbde4feffff 01b5ecfeffff 8bd7 }
            // n = 6, score = 200
            //   03b090c14200         | add                 esi, dword ptr [eax + 0x42c190]
            //   03b40514ffffff       | add                 esi, dword ptr [ebp + eax - 0xec]
            //   03f7                 | add                 esi, edi
            //   8bbde4feffff         | mov                 edi, dword ptr [ebp - 0x11c]
            //   01b5ecfeffff         | add                 dword ptr [ebp - 0x114], esi
            //   8bd7                 | mov                 edx, edi

        $sequence_7 = { 03d3 8b0c8528754300 8a0433 43 88440a2e 8b55b4 }
            // n = 6, score = 200
            //   03d3                 | add                 edx, ebx
            //   8b0c8528754300       | mov                 ecx, dword ptr [eax*4 + 0x437528]
            //   8a0433               | mov                 al, byte ptr [ebx + esi]
            //   43                   | inc                 ebx
            //   88440a2e             | mov                 byte ptr [edx + ecx + 0x2e], al
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]

        $sequence_8 = { 0fb6b1104b4300 8bca c1e918 c1e608 0fb689104b4300 }
            // n = 5, score = 200
            //   0fb6b1104b4300       | movzx               esi, byte ptr [ecx + 0x434b10]
            //   8bca                 | mov                 ecx, edx
            //   c1e918               | shr                 ecx, 0x18
            //   c1e608               | shl                 esi, 8
            //   0fb689104b4300       | movzx               ecx, byte ptr [ecx + 0x434b10]

        $sequence_9 = { 3385ecfeffff 03f0 c1ca0d 8b85f8feffff 03b07cc14200 8bc1 c1c00a }
            // n = 7, score = 200
            //   3385ecfeffff         | xor                 eax, dword ptr [ebp - 0x114]
            //   03f0                 | add                 esi, eax
            //   c1ca0d               | ror                 edx, 0xd
            //   8b85f8feffff         | mov                 eax, dword ptr [ebp - 0x108]
            //   03b07cc14200         | add                 esi, dword ptr [eax + 0x42c17c]
            //   8bc1                 | mov                 eax, ecx
            //   c1c00a               | rol                 eax, 0xa

    condition:
        7 of them and filesize < 483328
}