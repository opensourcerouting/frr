:description: Learn how to get started with Topotato for FRRouting

=======================
Welcome to Topotato 🔝🥔
=======================

Topotato is a work-in-progress test framework designed for conducting system-level conformance tests for FRRouting.
Its primary purpose is to execute FRR through various scenarios and validate its behavior.

Goals
-----

The creation of Topotato was motivated by addressing the limitations of the existing FRR test framework, topotests.

Topotato aims to achieve the following objectives:

- Enhance the readability and comprehensibility of tests, particularly when failures occur.
- Improve the reliability of tests, ensuring consistent outcomes irrespective of factors like system load, parallelization, execution order, operating system, or architecture.
- Simplify the test-writing process.
- Minimize the variability in expressing a specific test, ideally reducing it to a single way. This streamlines the process of identifying the correct approach to articulate a test condition, minimizing the potential for creating unstable tests (i.e., flaky tests). A standardized approach to expressing tests also reduces the learning curve and facilitates troubleshooting when a test fails.
- Enhance the utility of test reports, primarily for failure cases but also for successful ones. Test behavior and reasons for failure should be readily understandable without the need for extensive investigation, debugging statements, or repeated test runs.
- Enable easy execution of the test suite on developers' local development systems, ensuring accessibility and speed.

Secondary Goals
---------------

In addition to the primary objectives, Topotato also aims to achieve the following secondary goals, which are influenced by the aforementioned aims:

- Encapsulate tests within a single file to eliminate the need to navigate through multiple files.
- Replace hardcoded IP addresses with semantic expressions to improve readability. For instance, while ``192.168.13.57`` is an opaque IPv4 address, the expression ``r1.iface_to('r2').ip4[0]`` could represent the same address while being more comprehensible and easier to maintain.
- Enable the test suite to run without necessitating "root" access to the system or the installation of FRR. This approach ensures ease of execution and guarantees that the test suite cannot disrupt the developer's system due to kernel-level protection. Additionally, it mitigates issues stemming from broken or mismatched installations.
- Support FreeBSD.