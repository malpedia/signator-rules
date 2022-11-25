rule win_karma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.karma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.karma"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 6683fa20 740a 6683fa2e 7506 }
            // n = 4, score = 100
            //   6683fa20             | cmp                 dx, 0x20
            //   740a                 | je                  0xc
            //   6683fa2e             | cmp                 dx, 0x2e
            //   7506                 | jne                 8

        $sequence_1 = { 8d57fe 03c9 0fb70411 8d5202 }
            // n = 4, score = 100
            //   8d57fe               | lea                 edx, [edi - 2]
            //   03c9                 | add                 ecx, ecx
            //   0fb70411             | movzx               eax, word ptr [ecx + edx]
            //   8d5202               | lea                 edx, [edx + 2]

        $sequence_2 = { ff15???????? 8b35???????? ffd6 83f806 0f8475010000 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   83f806               | cmp                 eax, 6
            //   0f8475010000         | je                  0x17b

        $sequence_3 = { 0fb6480f 884aff 0fb64c06ff 884aeb 83ef01 }
            // n = 5, score = 100
            //   0fb6480f             | movzx               ecx, byte ptr [eax + 0xf]
            //   884aff               | mov                 byte ptr [edx - 1], cl
            //   0fb64c06ff           | movzx               ecx, byte ptr [esi + eax - 1]
            //   884aeb               | mov                 byte ptr [edx - 0x15], cl
            //   83ef01               | sub                 edi, 1

        $sequence_4 = { 50 ffd3 ff74242c 6a00 ff15???????? 50 ffd3 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd3                 | call                ebx

        $sequence_5 = { 50 6800710200 56 ff742420 ff15???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   6800710200           | push                0x27100
            //   56                   | push                esi
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff15????????         |                     

        $sequence_6 = { 57 ff742420 ff15???????? 6a00 8d442444 50 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   50                   | push                eax

        $sequence_7 = { c1e918 8847fc 884ffd 83fa40 }
            // n = 4, score = 100
            //   c1e918               | shr                 ecx, 0x18
            //   8847fc               | mov                 byte ptr [edi - 4], al
            //   884ffd               | mov                 byte ptr [edi - 3], cl
            //   83fa40               | cmp                 edx, 0x40

        $sequence_8 = { 8d4de0 e8???????? 8b5508 8bc6 c1e805 8bce }
            // n = 6, score = 100
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   e8????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8bc6                 | mov                 eax, esi
            //   c1e805               | shr                 eax, 5
            //   8bce                 | mov                 ecx, esi

        $sequence_9 = { 33ff 85f6 7e1a 8b1d???????? }
            // n = 4, score = 100
            //   33ff                 | xor                 edi, edi
            //   85f6                 | test                esi, esi
            //   7e1a                 | jle                 0x1c
            //   8b1d????????         |                     

    condition:
        7 of them and filesize < 49208
}