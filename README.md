# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2021-10-08

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2021-10-08
Samples (all):                              11279
Samples (detectable):                        4597
Families:                                    2187
-------------------------------------------------
Families covered by rules:                   1026
Rules without FPs:                           1018
Rules without FNs:                            954
'Clean' Rules:                                949
-------------------------------------------------
True Positives:                              4415
False Positives:                               17
True Negatives:                              5312
False Negatives:                              182
-------------------------------------------------
PPV / Precision:                            0.996
TPR / Recall:                               0.960
F1:                                         0.978
```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
