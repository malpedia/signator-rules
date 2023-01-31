rule win_malumpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.malumpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.malumpos"
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
        $sequence_0 = { 25ffffffff f8 ff45fc 0fb705???????? 8b55fc 8d0441 }
            // n = 6, score = 100
            //   25ffffffff           | and                 eax, 0xffffffff
            //   f8                   | clc                 
            //   ff45fc               | inc                 dword ptr [ebp - 4]
            //   0fb705????????       |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8d0441               | lea                 eax, [ecx + eax*2]

        $sequence_1 = { 807d0801 7515 be???????? e8???????? }
            // n = 4, score = 100
            //   807d0801             | cmp                 byte ptr [ebp + 8], 1
            //   7515                 | jne                 0x17
            //   be????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 59 8d45cc 50 ff15???????? 6a44 }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a44                 | push                0x44

        $sequence_3 = { 51 81f300000000 59 c0c7e0 6683ce00 7403 c0c748 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   81f300000000         | xor                 ebx, 0
            //   59                   | pop                 ecx
            //   c0c7e0               | rol                 bh, 0xe0
            //   6683ce00             | or                  si, 0
            //   7403                 | je                  5
            //   c0c748               | rol                 bh, 0x48

        $sequence_4 = { 8bff 55 8d6c2488 81ec84000000 8a4601 83657400 57 }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8d6c2488             | lea                 ebp, [esp - 0x78]
            //   81ec84000000         | sub                 esp, 0x84
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   83657400             | and                 dword ptr [ebp + 0x74], 0
            //   57                   | push                edi

        $sequence_5 = { e8???????? 50 e8???????? 8bf0 8d8500fdffff 50 ff35???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d8500fdffff         | lea                 eax, [ebp - 0x300]
            //   50                   | push                eax
            //   ff35????????         |                     

        $sequence_6 = { 81cb00000000 5b 7c05 53 80c400 5b f9 }
            // n = 7, score = 100
            //   81cb00000000         | or                  ebx, 0
            //   5b                   | pop                 ebx
            //   7c05                 | jl                  7
            //   53                   | push                ebx
            //   80c400               | add                 ah, 0
            //   5b                   | pop                 ebx
            //   f9                   | stc                 

        $sequence_7 = { 66c1c600 5d 81cd00000000 7505 }
            // n = 4, score = 100
            //   66c1c600             | rol                 si, 0
            //   5d                   | pop                 ebp
            //   81cd00000000         | or                  ebp, 0
            //   7505                 | jne                 7

        $sequence_8 = { 55 8d6c2488 81ec84000000 8a4601 83657400 57 0fb6f8 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8d6c2488             | lea                 ebp, [esp - 0x78]
            //   81ec84000000         | sub                 esp, 0x84
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   83657400             | and                 dword ptr [ebp + 0x74], 0
            //   57                   | push                edi
            //   0fb6f8               | movzx               edi, al

        $sequence_9 = { 8d4520 50 ff15???????? 8d4520 }
            // n = 4, score = 100
            //   8d4520               | lea                 eax, [ebp + 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d4520               | lea                 eax, [ebp + 0x20]

    condition:
        7 of them and filesize < 542720
}