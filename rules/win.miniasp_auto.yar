rule win_miniasp_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.miniasp."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miniasp"
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
        $sequence_0 = { 75e2 8bbd18dfffff 8bb520dfffff 8b851cdfffff 8bc8 c1e902 }
            // n = 6, score = 100
            //   75e2                 | jne                 0xffffffe4
            //   8bbd18dfffff         | mov                 edi, dword ptr [ebp - 0x20e8]
            //   8bb520dfffff         | mov                 esi, dword ptr [ebp - 0x20e0]
            //   8b851cdfffff         | mov                 eax, dword ptr [ebp - 0x20e4]
            //   8bc8                 | mov                 ecx, eax
            //   c1e902               | shr                 ecx, 2

        $sequence_1 = { eb17 6a00 ff75fc ff15???????? ff75fc ff15???????? }
            // n = 6, score = 100
            //   eb17                 | jmp                 0x19
            //   6a00                 | push                0
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     

        $sequence_2 = { c745f04cd24000 68???????? 8d45f0 50 e8???????? 6800000080 6a36 }
            // n = 7, score = 100
            //   c745f04cd24000       | mov                 dword ptr [ebp - 0x10], 0x40d24c
            //   68????????           |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6800000080           | push                0x80000000
            //   6a36                 | push                0x36

        $sequence_3 = { c780b800000000040000 6800001000 e8???????? 59 }
            // n = 4, score = 100
            //   c780b800000000040000     | mov    dword ptr [eax + 0xb8], 0x400
            //   6800001000           | push                0x100000
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_4 = { c1e810 25ffff0000 0fb7c0 8945b0 8b45b4 8945a4 }
            // n = 6, score = 100
            //   c1e810               | shr                 eax, 0x10
            //   25ffff0000           | and                 eax, 0xffff
            //   0fb7c0               | movzx               eax, ax
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax

        $sequence_5 = { ff7508 e8???????? 59 59 3b4508 0f85bb000000 8d8dd8dfffff }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]
            //   0f85bb000000         | jne                 0xc1
            //   8d8dd8dfffff         | lea                 ecx, [ebp - 0x2028]

        $sequence_6 = { 837dfc00 0f8e1e010000 ff75fc 8b45bc ffb0b4000000 ff750c }
            // n = 6, score = 100
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   0f8e1e010000         | jle                 0x124
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   ffb0b4000000         | push                dword ptr [eax + 0xb4]
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_7 = { 8885a3deffff ff85a4deffff 80bda3deffff00 75e2 8bbda4deffff be???????? }
            // n = 6, score = 100
            //   8885a3deffff         | mov                 byte ptr [ebp - 0x215d], al
            //   ff85a4deffff         | inc                 dword ptr [ebp - 0x215c]
            //   80bda3deffff00       | cmp                 byte ptr [ebp - 0x215d], 0
            //   75e2                 | jne                 0xffffffe4
            //   8bbda4deffff         | mov                 edi, dword ptr [ebp - 0x215c]
            //   be????????           |                     

        $sequence_8 = { 80bdcbfbffff00 75e3 8b85d0fbffff 2b85ccfbffff 8b8dccfbffff 898dc4fbffff 8985c0fbffff }
            // n = 7, score = 100
            //   80bdcbfbffff00       | cmp                 byte ptr [ebp - 0x435], 0
            //   75e3                 | jne                 0xffffffe5
            //   8b85d0fbffff         | mov                 eax, dword ptr [ebp - 0x430]
            //   2b85ccfbffff         | sub                 eax, dword ptr [ebp - 0x434]
            //   8b8dccfbffff         | mov                 ecx, dword ptr [ebp - 0x434]
            //   898dc4fbffff         | mov                 dword ptr [ebp - 0x43c], ecx
            //   8985c0fbffff         | mov                 dword ptr [ebp - 0x440], eax

        $sequence_9 = { 89857cdeffff 8b857cdeffff 8a4001 88857bdeffff ff857cdeffff 80bd7bdeffff00 75e2 }
            // n = 7, score = 100
            //   89857cdeffff         | mov                 dword ptr [ebp - 0x2184], eax
            //   8b857cdeffff         | mov                 eax, dword ptr [ebp - 0x2184]
            //   8a4001               | mov                 al, byte ptr [eax + 1]
            //   88857bdeffff         | mov                 byte ptr [ebp - 0x2185], al
            //   ff857cdeffff         | inc                 dword ptr [ebp - 0x2184]
            //   80bd7bdeffff00       | cmp                 byte ptr [ebp - 0x2185], 0
            //   75e2                 | jne                 0xffffffe4

    condition:
        7 of them and filesize < 139264
}