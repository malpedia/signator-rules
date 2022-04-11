rule win_ketrican_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ketrican."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrican"
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
        $sequence_0 = { 8965f0 33db 895dfc 33c0 }
            // n = 4, score = 700
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   33db                 | xor                 ebx, ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 680e000780 e8???????? cc 8b06 83e810 8b08 395008 }
            // n = 7, score = 600
            //   680e000780           | push                0x8007000e
            //   e8????????           |                     
            //   cc                   | int3                
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83e810               | sub                 eax, 0x10
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   395008               | cmp                 dword ptr [eax + 8], edx

        $sequence_2 = { e8???????? 83c010 8906 c3 56 8bf1 57 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   83c010               | add                 eax, 0x10
            //   8906                 | mov                 dword ptr [esi], eax
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi

        $sequence_3 = { 5e 8901 5b 5d c20800 680e000780 e8???????? }
            // n = 7, score = 600
            //   5e                   | pop                 esi
            //   8901                 | mov                 dword ptr [ecx], eax
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   680e000780           | push                0x8007000e
            //   e8????????           |                     

        $sequence_4 = { 8bc1 8945f0 834dfcff e8???????? }
            // n = 4, score = 600
            //   8bc1                 | mov                 eax, ecx
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   e8????????           |                     

        $sequence_5 = { 7417 6a0a 6a1f 68???????? }
            // n = 4, score = 600
            //   7417                 | je                  0x19
            //   6a0a                 | push                0xa
            //   6a1f                 | push                0x1f
            //   68????????           |                     

        $sequence_6 = { 8bd1 e8???????? 5f 5e c3 55 }
            // n = 6, score = 600
            //   8bd1                 | mov                 edx, ecx
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_7 = { 5d c20400 55 8bec 8b4508 894508 68???????? }
            // n = 7, score = 600
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   68????????           |                     

        $sequence_8 = { 8975fc 8b7508 83650800 8d48fd }
            // n = 4, score = 500
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   8d48fd               | lea                 ecx, dword ptr [eax - 3]

        $sequence_9 = { c1e308 e8???????? 0fbec0 0bd8 8bc7 }
            // n = 5, score = 500
            //   c1e308               | shl                 ebx, 8
            //   e8????????           |                     
            //   0fbec0               | movsx               eax, al
            //   0bd8                 | or                  ebx, eax
            //   8bc7                 | mov                 eax, edi

        $sequence_10 = { 8945d0 395dec 740b 8818 }
            // n = 4, score = 500
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   395dec               | cmp                 dword ptr [ebp - 0x14], ebx
            //   740b                 | je                  0xd
            //   8818                 | mov                 byte ptr [eax], bl

        $sequence_11 = { 57 8d7001 33db 8a08 40 3acb 75f9 }
            // n = 7, score = 500
            //   57                   | push                edi
            //   8d7001               | lea                 esi, dword ptr [eax + 1]
            //   33db                 | xor                 ebx, ebx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax
            //   3acb                 | cmp                 cl, bl
            //   75f9                 | jne                 0xfffffffb

        $sequence_12 = { 6a6c 58 668945e6 668945e8 33c0 }
            // n = 5, score = 500
            //   6a6c                 | push                0x6c
            //   58                   | pop                 eax
            //   668945e6             | mov                 word ptr [ebp - 0x1a], ax
            //   668945e8             | mov                 word ptr [ebp - 0x18], ax
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 83e00f 8bcf c1e916 c1e002 83e103 0bc1 }
            // n = 6, score = 500
            //   83e00f               | and                 eax, 0xf
            //   8bcf                 | mov                 ecx, edi
            //   c1e916               | shr                 ecx, 0x16
            //   c1e002               | shl                 eax, 2
            //   83e103               | and                 ecx, 3
            //   0bc1                 | or                  eax, ecx

        $sequence_14 = { 8bc7 c1e802 83e03f c1e308 e8???????? 8345fc03 0fbec0 }
            // n = 7, score = 500
            //   8bc7                 | mov                 eax, edi
            //   c1e802               | shr                 eax, 2
            //   83e03f               | and                 eax, 0x3f
            //   c1e308               | shl                 ebx, 8
            //   e8????????           |                     
            //   8345fc03             | add                 dword ptr [ebp - 4], 3
            //   0fbec0               | movsx               eax, al

        $sequence_15 = { c705????????98824100 a3???????? c605????????00 e8???????? 59 c3 68???????? }
            // n = 7, score = 100
            //   c705????????98824100     |     
            //   a3????????           |                     
            //   c605????????00       |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   68????????           |                     

        $sequence_16 = { 33c8 e8???????? 8b8ae8060000 33c8 e8???????? }
            // n = 5, score = 100
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   8b8ae8060000         | mov                 ecx, dword ptr [edx + 0x6e8]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     

        $sequence_17 = { e8???????? 8b8a8c2f0000 33c8 e8???????? b8???????? e9???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b8a8c2f0000         | mov                 ecx, dword ptr [edx + 0x2f8c]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     

        $sequence_18 = { b9???????? e9???????? c705????????ac824100 c3 b9???????? }
            // n = 5, score = 100
            //   b9????????           |                     
            //   e9????????           |                     
            //   c705????????ac824100     |     
            //   c3                   | ret                 
            //   b9????????           |                     

        $sequence_19 = { 8d420c 8b8a54ffffff 33c8 e8???????? 8b8adc090000 33c8 }
            // n = 6, score = 100
            //   8d420c               | lea                 eax, dword ptr [edx + 0xc]
            //   8b8a54ffffff         | mov                 ecx, dword ptr [edx - 0xac]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   8b8adc090000         | mov                 ecx, dword ptr [edx + 0x9dc]
            //   33c8                 | xor                 ecx, eax

        $sequence_20 = { 8d4de0 e9???????? 8d4db8 e9???????? 8d4ddc }
            // n = 5, score = 100
            //   8d4de0               | lea                 ecx, dword ptr [ebp - 0x20]
            //   e9????????           |                     
            //   8d4db8               | lea                 ecx, dword ptr [ebp - 0x48]
            //   e9????????           |                     
            //   8d4ddc               | lea                 ecx, dword ptr [ebp - 0x24]

        $sequence_21 = { e9???????? 8b45d4 83e001 0f840c000000 8365d4fe 8d4da4 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   83e001               | and                 eax, 1
            //   0f840c000000         | je                  0x12
            //   8365d4fe             | and                 dword ptr [ebp - 0x2c], 0xfffffffe
            //   8d4da4               | lea                 ecx, dword ptr [ebp - 0x5c]
            //   e9????????           |                     

        $sequence_22 = { 8b8aa4feffff 33c8 e8???????? 8b8abc060000 33c8 }
            // n = 5, score = 100
            //   8b8aa4feffff         | mov                 ecx, dword ptr [edx - 0x15c]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   8b8abc060000         | mov                 ecx, dword ptr [edx + 0x6bc]
            //   33c8                 | xor                 ecx, eax

    condition:
        7 of them and filesize < 1449984
}