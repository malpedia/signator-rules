rule win_unidentified_069_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.unidentified_069."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_069"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 68f0ae9387 e8???????? 8bf8 85ff 0f84a0000000 6a0b 8d44243c }
            // n = 7, score = 100
            //   68f0ae9387           | push                0x8793aef0
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f84a0000000         | je                  0xa6
            //   6a0b                 | push                0xb
            //   8d44243c             | lea                 eax, dword ptr [esp + 0x3c]

        $sequence_1 = { 72ee 33c9 66890c46 5e 5b 8be5 5d }
            // n = 7, score = 100
            //   72ee                 | jb                  0xfffffff0
            //   33c9                 | xor                 ecx, ecx
            //   66890c46             | mov                 word ptr [esi + eax*2], cx
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_2 = { c1ef04 2bde 47 8b4510 6a10 50 }
            // n = 6, score = 100
            //   c1ef04               | shr                 edi, 4
            //   2bde                 | sub                 ebx, esi
            //   47                   | inc                 edi
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   6a10                 | push                0x10
            //   50                   | push                eax

        $sequence_3 = { 85c0 740c 8d85f8fdffff 50 e8???????? c9 c3 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   8d85f8fdffff         | lea                 eax, dword ptr [ebp - 0x208]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_4 = { 3311 83c104 3339 c1eb10 897df4 8b7df8 }
            // n = 6, score = 100
            //   3311                 | xor                 edx, dword ptr [ecx]
            //   83c104               | add                 ecx, 4
            //   3339                 | xor                 edi, dword ptr [ecx]
            //   c1eb10               | shr                 ebx, 0x10
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]

        $sequence_5 = { 8d75b8 83c8ff e8???????? 6a0a 8d8ff0090000 6a00 }
            // n = 6, score = 100
            //   8d75b8               | lea                 esi, dword ptr [ebp - 0x48]
            //   83c8ff               | or                  eax, 0xffffffff
            //   e8????????           |                     
            //   6a0a                 | push                0xa
            //   8d8ff0090000         | lea                 ecx, dword ptr [edi + 0x9f0]
            //   6a00                 | push                0

        $sequence_6 = { ff550c 46 8d04b7 833800 75d8 f6450801 }
            // n = 6, score = 100
            //   ff550c               | call                dword ptr [ebp + 0xc]
            //   46                   | inc                 esi
            //   8d04b7               | lea                 eax, dword ptr [edi + esi*4]
            //   833800               | cmp                 dword ptr [eax], 0
            //   75d8                 | jne                 0xffffffda
            //   f6450801             | test                byte ptr [ebp + 8], 1

        $sequence_7 = { 8d4510 50 8b450c 03d8 53 ff7508 ff15???????? }
            // n = 7, score = 100
            //   8d4510               | lea                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   03d8                 | add                 ebx, eax
            //   53                   | push                ebx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_8 = { 7703 80c320 8aca 80e941 80f919 7705 80c220 }
            // n = 7, score = 100
            //   7703                 | ja                  5
            //   80c320               | add                 bl, 0x20
            //   8aca                 | mov                 cl, dl
            //   80e941               | sub                 cl, 0x41
            //   80f919               | cmp                 cl, 0x19
            //   7705                 | ja                  7
            //   80c220               | add                 dl, 0x20

        $sequence_9 = { a3???????? ffd6 a3???????? 391d???????? 7430 391d???????? 7428 }
            // n = 7, score = 100
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   391d????????         |                     
            //   7430                 | je                  0x32
            //   391d????????         |                     
            //   7428                 | je                  0x2a

    condition:
        7 of them and filesize < 434176
}