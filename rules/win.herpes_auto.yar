rule win_herpes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.herpes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.herpes"
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
        $sequence_0 = { 57 ff15???????? ff7594 57 ff15???????? 57 8b3d???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff7594               | push                dword ptr [ebp - 0x6c]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   8b3d????????         |                     

        $sequence_1 = { 50 51 8d95fcfbffff 52 ff15???????? 8d85fcfbffff 8d5001 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d95fcfbffff         | lea                 edx, dword ptr [ebp - 0x404]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d85fcfbffff         | lea                 eax, dword ptr [ebp - 0x404]
            //   8d5001               | lea                 edx, dword ptr [eax + 1]

        $sequence_2 = { 8bb57cffffff e9???????? 8bb578ffffff e9???????? 8b542408 8d420c }
            // n = 6, score = 100
            //   8bb57cffffff         | mov                 esi, dword ptr [ebp - 0x84]
            //   e9????????           |                     
            //   8bb578ffffff         | mov                 esi, dword ptr [ebp - 0x88]
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d420c               | lea                 eax, dword ptr [edx + 0xc]

        $sequence_3 = { ffd7 68???????? ffb6f8010000 898698000000 ffd7 68???????? ffb6f8010000 }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   ffb6f8010000         | push                dword ptr [esi + 0x1f8]
            //   898698000000         | mov                 dword ptr [esi + 0x98], eax
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   ffb6f8010000         | push                dword ptr [esi + 0x1f8]

        $sequence_4 = { 7202 8bd6 837d1c10 8b7d08 7303 8d7d08 83fa04 }
            // n = 7, score = 100
            //   7202                 | jb                  4
            //   8bd6                 | mov                 edx, esi
            //   837d1c10             | cmp                 dword ptr [ebp + 0x1c], 0x10
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   7303                 | jae                 5
            //   8d7d08               | lea                 edi, dword ptr [ebp + 8]
            //   83fa04               | cmp                 edx, 4

        $sequence_5 = { ffd7 68???????? ffb6f8010000 898680000000 }
            // n = 4, score = 100
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   ffb6f8010000         | push                dword ptr [esi + 0x1f8]
            //   898680000000         | mov                 dword ptr [esi + 0x80], eax

        $sequence_6 = { b302 8d4508 8dbd88fcffff 885dfc e8???????? }
            // n = 5, score = 100
            //   b302                 | mov                 bl, 2
            //   8d4508               | lea                 eax, dword ptr [ebp + 8]
            //   8dbd88fcffff         | lea                 edi, dword ptr [ebp - 0x378]
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   e8????????           |                     

        $sequence_7 = { 8d4d80 e8???????? 83c41c 8bf8 }
            // n = 4, score = 100
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { 50 8d85fcfbffff 50 53 ffd6 57 8d85dcfbffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d85fcfbffff         | lea                 eax, dword ptr [ebp - 0x404]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   57                   | push                edi
            //   8d85dcfbffff         | lea                 eax, dword ptr [ebp - 0x424]

        $sequence_9 = { 83ff21 7512 68???????? e8???????? 83c404 5e 5d }
            // n = 7, score = 100
            //   83ff21               | cmp                 edi, 0x21
            //   7512                 | jne                 0x14
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

    condition:
        7 of them and filesize < 319488
}