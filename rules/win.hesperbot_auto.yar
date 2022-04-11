rule win_hesperbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.hesperbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hesperbot"
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
        $sequence_0 = { ff7508 c745fc04000000 33db e8???????? 83c40c 85c0 7e0d }
            // n = 7, score = 500
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c745fc04000000       | mov                 dword ptr [ebp - 4], 4
            //   33db                 | xor                 ebx, ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7e0d                 | jle                 0xf

        $sequence_1 = { 33ff c1ed0e 0bf5 33ce 8b742420 }
            // n = 5, score = 500
            //   33ff                 | xor                 edi, edi
            //   c1ed0e               | shr                 ebp, 0xe
            //   0bf5                 | or                  esi, ebp
            //   33ce                 | xor                 ecx, esi
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]

        $sequence_2 = { e8???????? 59 33c9 4e 7436 8a0419 }
            // n = 6, score = 500
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   33c9                 | xor                 ecx, ecx
            //   4e                   | dec                 esi
            //   7436                 | je                  0x38
            //   8a0419               | mov                 al, byte ptr [ecx + ebx]

        $sequence_3 = { 89049e 8b07 43 ff45f8 }
            // n = 4, score = 500
            //   89049e               | mov                 dword ptr [esi + ebx*4], eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   43                   | inc                 ebx
            //   ff45f8               | inc                 dword ptr [ebp - 8]

        $sequence_4 = { 297508 75b3 5e 5b 5f c9 }
            // n = 6, score = 500
            //   297508               | sub                 dword ptr [ebp + 8], esi
            //   75b3                 | jne                 0xffffffb5
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   c9                   | leave               

        $sequence_5 = { 7505 397b08 75db 56 e8???????? 59 }
            // n = 6, score = 500
            //   7505                 | jne                 7
            //   397b08               | cmp                 dword ptr [ebx + 8], edi
            //   75db                 | jne                 0xffffffdd
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_6 = { 5f 5b 5d c3 55 8bec 81ecd8000000 }
            // n = 7, score = 500
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecd8000000         | sub                 esp, 0xd8

        $sequence_7 = { 33c3 33c2 d1ed c1e71f 0bfd 33f7 }
            // n = 6, score = 500
            //   33c3                 | xor                 eax, ebx
            //   33c2                 | xor                 eax, edx
            //   d1ed                 | shr                 ebp, 1
            //   c1e71f               | shl                 edi, 0x1f
            //   0bfd                 | or                  edi, ebp
            //   33f7                 | xor                 esi, edi

        $sequence_8 = { 5e 5b c3 83f8ff 7505 e8???????? }
            // n = 6, score = 500
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   83f8ff               | cmp                 eax, -1
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_9 = { 75dc ff7508 8bf3 e8???????? 59 85c0 }
            // n = 6, score = 500
            //   75dc                 | jne                 0xffffffde
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bf3                 | mov                 esi, ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 188416
}