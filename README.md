# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2022-04-11

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2022-04-11
Samples (all):                              11851
Samples (detectable):                        4857
Families:                                    2397
-------------------------------------------------
Families covered by rules:                   1120
Rules without FPs:                           1112
Rules without FNs:                           1053
'Clean' Rules:                               1048
-------------------------------------------------
True Positives:                              4683 
False Positives:                               22
True Negatives:                              5575
False Negatives:                              174
-------------------------------------------------
PPV / Precision:                            0.995
TPR / Recall:                               0.964
F1:                                         0.980
```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
