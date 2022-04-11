rule win_batchwiper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.batchwiper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.batchwiper"
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
        $sequence_0 = { 83c001 8bce c1e908 330c9de8904000 }
            // n = 4, score = 100
            //   83c001               | add                 eax, 1
            //   8bce                 | mov                 ecx, esi
            //   c1e908               | shr                 ecx, 8
            //   330c9de8904000       | xor                 ecx, dword ptr [ebx*4 + 0x4090e8]

        $sequence_1 = { 8b0424 894510 8b442408 894514 8b442404 }
            // n = 5, score = 100
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   894514               | mov                 dword ptr [ebp + 0x14], eax
            //   8b442404             | mov                 eax, dword ptr [esp + 4]

        $sequence_2 = { 8b442408 894514 8b442404 894518 8d44240c }
            // n = 5, score = 100
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   894514               | mov                 dword ptr [ebp + 0x14], eax
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   894518               | mov                 dword ptr [ebp + 0x18], eax
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]

        $sequence_3 = { e8???????? 50 31db 3b1c24 756b }
            // n = 5, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   31db                 | xor                 ebx, ebx
            //   3b1c24               | cmp                 ebx, dword ptr [esp]
            //   756b                 | jne                 0x6d

        $sequence_4 = { 89d8 e8???????? 89c3 83fb01 7531 ff35???????? }
            // n = 6, score = 100
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     
            //   89c3                 | mov                 ebx, eax
            //   83fb01               | cmp                 ebx, 1
            //   7531                 | jne                 0x33
            //   ff35????????         |                     

        $sequence_5 = { 83fb01 7531 ff35???????? ba???????? e8???????? 8b15???????? e8???????? }
            // n = 7, score = 100
            //   83fb01               | cmp                 ebx, 1
            //   7531                 | jne                 0x33
            //   ff35????????         |                     
            //   ba????????           |                     
            //   e8????????           |                     
            //   8b15????????         |                     
            //   e8????????           |                     

        $sequence_6 = { e8???????? 89c3 83fb01 7531 ff35???????? ba???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   89c3                 | mov                 ebx, eax
            //   83fb01               | cmp                 ebx, 1
            //   7531                 | jne                 0x33
            //   ff35????????         |                     
            //   ba????????           |                     

        $sequence_7 = { e8???????? 8d0d28b14000 5a e8???????? 8b15???????? ff35???????? e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d0d28b14000         | lea                 ecx, dword ptr [0x40b128]
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   8b15????????         |                     
            //   ff35????????         |                     
            //   e8????????           |                     

        $sequence_8 = { ba???????? e8???????? 8d0d28b14000 5a e8???????? 8b15???????? ff35???????? }
            // n = 7, score = 100
            //   ba????????           |                     
            //   e8????????           |                     
            //   8d0d28b14000         | lea                 ecx, dword ptr [0x40b128]
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   8b15????????         |                     
            //   ff35????????         |                     

        $sequence_9 = { c705????????02000000 893d???????? c705????????dd424000 c705????????80464000 c705????????da464000 c705????????00474000 }
            // n = 6, score = 100
            //   c705????????02000000     |     
            //   893d????????         |                     
            //   c705????????dd424000     |     
            //   c705????????80464000     |     
            //   c705????????da464000     |     
            //   c705????????00474000     |     

    condition:
        7 of them and filesize < 270336
}