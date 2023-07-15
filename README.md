# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2023-01-25

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2023-07-15
Samples (all):                              13328
Samples (detectable):                        5453
Families:                                    2871
-------------------------------------------------
Families covered by rules:                   1319
Rules without FPs:                           1308
Rules without FNs:                           1237
'Clean' Rules:                               1232
-------------------------------------------------
True Positives:                              5247
False Positives:                               24
True Negatives:                              6426
False Negatives:                              206
-------------------------------------------------
PPV / Precision:                            0.995
TPR / Recall:                               0.962
F1:                                         0.979
```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
