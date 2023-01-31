rule win_mbrlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.mbrlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlocker"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 89f7 8b4d10 8b550c ac 30c8 }
            // n = 5, score = 100
            //   89f7                 | mov                 edi, esi
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   ac                   | lodsb               al, byte ptr [esi]
            //   30c8                 | xor                 al, cl

        $sequence_1 = { 68fe000000 68???????? ffd7 83c408 }
            // n = 4, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   83c408               | add                 esp, 8

        $sequence_2 = { 8b7508 89f7 8b4d10 8b550c ac 30c8 }
            // n = 6, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   89f7                 | mov                 edi, esi
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   ac                   | lodsb               al, byte ptr [esi]
            //   30c8                 | xor                 al, cl

        $sequence_3 = { 89e5 60 8b7508 89f7 8b4d10 }
            // n = 5, score = 100
            //   89e5                 | mov                 ebp, esp
            //   60                   | pushal              
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   89f7                 | mov                 edi, esi
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

        $sequence_4 = { 68???????? ffd6 83c408 68ff000000 68fe000000 }
            // n = 5, score = 100
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   68ff000000           | push                0xff
            //   68fe000000           | push                0xfe

        $sequence_5 = { ff750c ff7508 68???????? ff25???????? }
            // n = 4, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68????????           |                     
            //   ff25????????         |                     

        $sequence_6 = { 31c8 e8???????? 68ac000000 68???????? ffd6 83c408 68ff000000 }
            // n = 7, score = 100
            //   31c8                 | xor                 eax, ecx
            //   e8????????           |                     
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   68ff000000           | push                0xff

        $sequence_7 = { 83c408 68ff000000 68fe000000 68???????? e8???????? }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   68ff000000           | push                0xff
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_8 = { 68fe000000 68???????? e8???????? e8???????? 68ff000000 68fe000000 }
            // n = 6, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68ff000000           | push                0xff
            //   68fe000000           | push                0xfe

        $sequence_9 = { 58 e8???????? 751e 6a10 }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   e8????????           |                     
            //   751e                 | jne                 0x20
            //   6a10                 | push                0x10

    condition:
        7 of them and filesize < 43008
}