rule win_thunderx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.thunderx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunderx"
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
        $sequence_0 = { 8bcb 8b5510 66397dfc 741b 83fa01 740d }
            // n = 6, score = 200
            //   8bcb                 | mov                 ecx, ebx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   66397dfc             | cmp                 word ptr [ebp - 4], di
            //   741b                 | je                  0x1d
            //   83fa01               | cmp                 edx, 1
            //   740d                 | je                  0xf

        $sequence_1 = { 50 e8???????? 8b4d8c 33c8 8b4590 03c1 894d8c }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4d8c               | mov                 ecx, dword ptr [ebp - 0x74]
            //   33c8                 | xor                 ecx, eax
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   03c1                 | add                 eax, ecx
            //   894d8c               | mov                 dword ptr [ebp - 0x74], ecx

        $sequence_2 = { 57 53 56 897e10 e8???????? 83c40c 881c37 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   53                   | push                ebx
            //   56                   | push                esi
            //   897e10               | mov                 dword ptr [esi + 0x10], edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   881c37               | mov                 byte ptr [edi + esi], bl

        $sequence_3 = { 8a8748054200 08441619 42 0fb64101 3bd0 76e5 83c102 }
            // n = 7, score = 200
            //   8a8748054200         | mov                 al, byte ptr [edi + 0x420548]
            //   08441619             | or                  byte ptr [esi + edx + 0x19], al
            //   42                   | inc                 edx
            //   0fb64101             | movzx               eax, byte ptr [ecx + 1]
            //   3bd0                 | cmp                 edx, eax
            //   76e5                 | jbe                 0xffffffe7
            //   83c102               | add                 ecx, 2

        $sequence_4 = { 53 6a00 e8???????? 59 50 e8???????? 33db }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx

        $sequence_5 = { 8d5110 3b02 7714 83791408 7202 }
            // n = 5, score = 200
            //   8d5110               | lea                 edx, dword ptr [ecx + 0x10]
            //   3b02                 | cmp                 eax, dword ptr [edx]
            //   7714                 | ja                  0x16
            //   83791408             | cmp                 dword ptr [ecx + 0x14], 8
            //   7202                 | jb                  4

        $sequence_6 = { 8bf0 56 e8???????? 6bce18 8bd8 891f 895f04 }
            // n = 7, score = 200
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   6bce18               | imul                ecx, esi, 0x18
            //   8bd8                 | mov                 ebx, eax
            //   891f                 | mov                 dword ptr [edi], ebx
            //   895f04               | mov                 dword ptr [edi + 4], ebx

        $sequence_7 = { 33c8 8b4598 03c1 894d8c 6a0d 50 e8???????? }
            // n = 7, score = 200
            //   33c8                 | xor                 ecx, eax
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]
            //   03c1                 | add                 eax, ecx
            //   894d8c               | mov                 dword ptr [ebp - 0x74], ecx
            //   6a0d                 | push                0xd
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 50 e8???????? 8b4da0 33c8 8b45a4 03c1 894da0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4da0               | mov                 ecx, dword ptr [ebp - 0x60]
            //   33c8                 | xor                 ecx, eax
            //   8b45a4               | mov                 eax, dword ptr [ebp - 0x5c]
            //   03c1                 | add                 eax, ecx
            //   894da0               | mov                 dword ptr [ebp - 0x60], ecx

        $sequence_9 = { 8b75fc 51 57 894e18 }
            // n = 4, score = 200
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   894e18               | mov                 dword ptr [esi + 0x18], ecx

    condition:
        7 of them and filesize < 319488
}