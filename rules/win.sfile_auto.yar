rule win_sfile_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.sfile."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sfile"
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
        $sequence_0 = { 0f8282fdffff 8b4df0 8b3d???????? 8b1d???????? 85c9 741e 8b45ec }
            // n = 7, score = 300
            //   0f8282fdffff         | jb                  0xfffffd88
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b3d????????         |                     
            //   8b1d????????         |                     
            //   85c9                 | test                ecx, ecx
            //   741e                 | je                  0x20
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_1 = { 5f 0500d1ffff 5e 8be5 5d c3 833d????????00 }
            // n = 7, score = 300
            //   5f                   | pop                 edi
            //   0500d1ffff           | add                 eax, 0xffffd100
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   833d????????00       |                     

        $sequence_2 = { 8b45fc 3bce 732e 8bd3 03c8 2bd0 8955e4 }
            // n = 7, score = 300
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   3bce                 | cmp                 ecx, esi
            //   732e                 | jae                 0x30
            //   8bd3                 | mov                 edx, ebx
            //   03c8                 | add                 ecx, eax
            //   2bd0                 | sub                 edx, eax
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx

        $sequence_3 = { 8b06 85c0 7421 ff7604 6a00 50 }
            // n = 6, score = 300
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23
            //   ff7604               | push                dword ptr [esi + 4]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_4 = { 8d4ddc e8???????? 8bf0 85f6 0f8524080000 8b3b 8bc7 }
            // n = 7, score = 300
            //   8d4ddc               | lea                 ecx, dword ptr [ebp - 0x24]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f8524080000         | jne                 0x82a
            //   8b3b                 | mov                 edi, dword ptr [ebx]
            //   8bc7                 | mov                 eax, edi

        $sequence_5 = { 8d0cdd00000000 8bc1 c1e818 0f1145e0 8845ec 8bc1 c1e810 }
            // n = 7, score = 300
            //   8d0cdd00000000       | lea                 ecx, dword ptr [ebx*8]
            //   8bc1                 | mov                 eax, ecx
            //   c1e818               | shr                 eax, 0x18
            //   0f1145e0             | movups              xmmword ptr [ebp - 0x20], xmm0
            //   8845ec               | mov                 byte ptr [ebp - 0x14], al
            //   8bc1                 | mov                 eax, ecx
            //   c1e810               | shr                 eax, 0x10

        $sequence_6 = { 57 51 ff7508 894d20 ff55f8 83c418 85c0 }
            // n = 7, score = 300
            //   57                   | push                edi
            //   51                   | push                ecx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   894d20               | mov                 dword ptr [ebp + 0x20], ecx
            //   ff55f8               | call                dword ptr [ebp - 8]
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax

        $sequence_7 = { 8bc1 8955ec 53 8945fc 56 8b585c 8b4518 }
            // n = 7, score = 300
            //   8bc1                 | mov                 eax, ecx
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   53                   | push                ebx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   8b585c               | mov                 ebx, dword ptr [eax + 0x5c]
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_8 = { 03c8 c1c30a 8b45bc 33d0 335598 0355c8 0355ac }
            // n = 7, score = 300
            //   03c8                 | add                 ecx, eax
            //   c1c30a               | rol                 ebx, 0xa
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   33d0                 | xor                 edx, eax
            //   335598               | xor                 edx, dword ptr [ebp - 0x68]
            //   0355c8               | add                 edx, dword ptr [ebp - 0x38]
            //   0355ac               | add                 edx, dword ptr [ebp - 0x54]

        $sequence_9 = { 8d45cc 83c10c 50 8bd1 e8???????? 8bf0 83c404 }
            // n = 7, score = 300
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   83c10c               | add                 ecx, 0xc
            //   50                   | push                eax
            //   8bd1                 | mov                 edx, ecx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 588800
}