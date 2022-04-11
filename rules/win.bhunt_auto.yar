rule win_bhunt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.bhunt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bhunt"
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
        $sequence_0 = { f5 66890e 8b0f 66f7c14a58 81c704000000 6681f91e38 33cb }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   66890e               | mov                 word ptr [esi], cx
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   66f7c14a58           | test                cx, 0x584a
            //   81c704000000         | add                 edi, 4
            //   6681f91e38           | cmp                 cx, 0x381e
            //   33cb                 | xor                 ecx, ebx

        $sequence_1 = { d0c0 85fa 80c652 6681d2cf71 32d8 c1d25e 660fbed6 }
            // n = 7, score = 100
            //   d0c0                 | rol                 al, 1
            //   85fa                 | test                edx, edi
            //   80c652               | add                 dh, 0x52
            //   6681d2cf71           | adc                 dx, 0x71cf
            //   32d8                 | xor                 bl, al
            //   c1d25e               | rcl                 edx, 0x5e
            //   660fbed6             | movsx               dx, dh

        $sequence_2 = { 40 663bde 81fc061c1e41 f9 0fc8 f5 f9 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   663bde               | cmp                 bx, si
            //   81fc061c1e41         | cmp                 esp, 0x411e1c06
            //   f9                   | stc                 
            //   0fc8                 | bswap               eax
            //   f5                   | cmc                 
            //   f9                   | stc                 

        $sequence_3 = { 92 51 015aaf 035ecf c54692 198f39f717ad 2b4aab }
            // n = 7, score = 100
            //   92                   | xchg                eax, edx
            //   51                   | push                ecx
            //   015aaf               | add                 dword ptr [edx - 0x51], ebx
            //   035ecf               | add                 ebx, dword ptr [esi - 0x31]
            //   c54692               | lds                 eax, ptr [esi - 0x6e]
            //   198f39f717ad         | sbb                 dword ptr [edi - 0x52e808c7], ecx
            //   2b4aab               | sub                 ecx, dword ptr [edx - 0x55]

        $sequence_4 = { 5e f7d1 23c4 660fbaf044 c0f40b 894c2500 fec0 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   f7d1                 | not                 ecx
            //   23c4                 | and                 eax, esp
            //   660fbaf044           | btr                 ax, 0x44
            //   c0f40b               | sal                 ah, 0xb
            //   894c2500             | mov                 dword ptr [ebp], ecx
            //   fec0                 | inc                 al

        $sequence_5 = { 68e9030000 ff7710 e8???????? c3 8b1d???????? 33f6 56 }
            // n = 7, score = 100
            //   68e9030000           | push                0x3e9
            //   ff7710               | push                dword ptr [edi + 0x10]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8b1d????????         |                     
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi

        $sequence_6 = { fd 7148 649e ae 29bd4e1045eb 7d7f bb59e05eb3 }
            // n = 7, score = 100
            //   fd                   | std                 
            //   7148                 | jno                 0x4a
            //   649e                 | sahf                
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   29bd4e1045eb         | sub                 dword ptr [ebp - 0x14baefb2], edi
            //   7d7f                 | jge                 0x81
            //   bb59e05eb3           | mov                 ebx, 0xb35ee059

        $sequence_7 = { 6689442500 1bd7 6685d7 81ef04000000 660fbed4 33d6 99 }
            // n = 7, score = 100
            //   6689442500           | mov                 word ptr [ebp], ax
            //   1bd7                 | sbb                 edx, edi
            //   6685d7               | test                di, dx
            //   81ef04000000         | sub                 edi, 4
            //   660fbed4             | movsx               dx, ah
            //   33d6                 | xor                 edx, esi
            //   99                   | cdq                 

        $sequence_8 = { fc 8e04a5???????? 33ef aa 3417 ed b877eefc1d }
            // n = 7, score = 100
            //   fc                   | cld                 
            //   8e04a5????????       |                     
            //   33ef                 | xor                 ebp, edi
            //   aa                   | stosb               byte ptr es:[edi], al
            //   3417                 | xor                 al, 0x17
            //   ed                   | in                  eax, dx
            //   b877eefc1d           | mov                 eax, 0x1dfcee77

        $sequence_9 = { ff7610 55 e8???????? 8bf8 8d45f0 50 }
            // n = 6, score = 100
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   55                   | push                ebp
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 19161088
}