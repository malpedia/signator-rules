rule win_arefty_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.arefty."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arefty"
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
        $sequence_0 = { 50 53 ff15???????? 680000a000 e8???????? 8bf8 83c404 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   680000a000           | push                0xa00000
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4

        $sequence_1 = { 50 8b07 68???????? 6a03 8d04b0 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   68????????           |                     
            //   6a03                 | push                3
            //   8d04b0               | lea                 eax, dword ptr [eax + esi*4]

        $sequence_2 = { 7409 57 e8???????? 83c404 83fbff 7407 53 }
            // n = 7, score = 400
            //   7409                 | je                  0xb
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83fbff               | cmp                 ebx, -1
            //   7407                 | je                  9
            //   53                   | push                ebx

        $sequence_3 = { 0fb6041e 50 8b07 68???????? }
            // n = 4, score = 400
            //   0fb6041e             | movzx               eax, byte ptr [esi + ebx]
            //   50                   | push                eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   68????????           |                     

        $sequence_4 = { 50 53 ff15???????? 680000a000 e8???????? }
            // n = 5, score = 400
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   680000a000           | push                0xa00000
            //   e8????????           |                     

        $sequence_5 = { 50 8b07 68???????? 6a03 8d04b0 50 e8???????? }
            // n = 7, score = 400
            //   50                   | push                eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   68????????           |                     
            //   6a03                 | push                3
            //   8d04b0               | lea                 eax, dword ptr [eax + esi*4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 0fb6041e 50 8b07 68???????? 6a03 }
            // n = 5, score = 400
            //   0fb6041e             | movzx               eax, byte ptr [esi + ebx]
            //   50                   | push                eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   68????????           |                     
            //   6a03                 | push                3

        $sequence_7 = { 8b07 68???????? 6a03 8d04b0 50 }
            // n = 5, score = 400
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   68????????           |                     
            //   6a03                 | push                3
            //   8d04b0               | lea                 eax, dword ptr [eax + esi*4]
            //   50                   | push                eax

        $sequence_8 = { ff15???????? 680000a000 e8???????? 8bf8 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   680000a000           | push                0xa00000
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_9 = { 53 ff15???????? 680000a000 e8???????? 8bf8 }
            // n = 5, score = 400
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   680000a000           | push                0xa00000
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 237568
}