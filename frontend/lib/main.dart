import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const NetworkSecurityScannerApp());
}

class NetworkSecurityScannerApp extends StatelessWidget {
  const NetworkSecurityScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Network Security Scanner',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF0E6B62),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF2F6F5),
        fontFamily: 'Georgia',
      ),
      home: const ScannerHomePage(),
    );
  }
}

String defaultApiBaseUrl() {
  if (kIsWeb) {
    return 'http://127.0.0.1:8000/api';
  }

  if (defaultTargetPlatform == TargetPlatform.android) {
    return 'http://10.0.2.2:8000/api';
  }

  return 'http://127.0.0.1:8000/api';
}

class ScannerHomePage extends StatefulWidget {
  const ScannerHomePage({super.key, this.autoLoadRules = true});

  final bool autoLoadRules;

  @override
  State<ScannerHomePage> createState() => _ScannerHomePageState();
}

class _ScannerHomePageState extends State<ScannerHomePage> {
  final TextEditingController _baseUrlController = TextEditingController(
    text: defaultApiBaseUrl(),
  );
  final TextEditingController _targetController = TextEditingController(text: '127.0.0.1');
  final TextEditingController _portRangeController = TextEditingController(text: '20-1024');
  final TextEditingController _timeoutController = TextEditingController(text: '0.2');

  final TextEditingController _sourceIpController = TextEditingController();
  final TextEditingController _rulePortController = TextEditingController();
  final TextEditingController _priorityController = TextEditingController(text: '100');
  final TextEditingController _ruleNoteController = TextEditingController();

  String _scanType = 'full_connect';
  String _ruleAction = 'allow';
  String _ruleProtocol = 'any';

  bool _isScanning = false;
  bool _isPollingScan = false;
  bool _isLoadingRules = false;
  bool _isSavingRule = false;
  bool _isSimulating = false;

  Timer? _scanPollTimer;
  String? _activeScanJobId;
  String _scanRunStatus = 'idle';
  int _scanScannedPorts = 0;
  int _scanTotalPorts = 0;
  double _scanPercent = 0;

  ScanResponsePayload? _lastScan;
  SimulationPayload? _simulation;
  List<FirewallRuleItem> _rules = [];

  @override
  void initState() {
    super.initState();
    if (widget.autoLoadRules) {
      _loadRules();
    }
  }

  @override
  void dispose() {
    _scanPollTimer?.cancel();
    _baseUrlController.dispose();
    _targetController.dispose();
    _portRangeController.dispose();
    _timeoutController.dispose();
    _sourceIpController.dispose();
    _rulePortController.dispose();
    _priorityController.dispose();
    _ruleNoteController.dispose();
    super.dispose();
  }

  BackendApiClient _client() {
    return BackendApiClient(baseUrl: _baseUrlController.text.trim());
  }

  Future<void> _loadRules() async {
    setState(() {
      _isLoadingRules = true;
    });

    try {
      final rules = await _client().listFirewallRules();
      if (!mounted) {
        return;
      }
      setState(() {
        _rules = rules;
      });
    } on DioException catch (error) {
      _showError(_readDioError(error));
    } catch (error) {
      _showError('Failed to load firewall rules: $error');
    } finally {
      if (mounted) {
        setState(() {
          _isLoadingRules = false;
        });
      }
    }
  }

  Future<void> _startScan() async {
    final target = _targetController.text.trim();
    final portRange = _portRangeController.text.trim();
    final timeout = double.tryParse(_timeoutController.text.trim());

    if (target.isEmpty) {
      _showError('Target IP/hostname is required.');
      return;
    }

    if (timeout == null) {
      _showError('Timeout must be a number, for example 0.2.');
      return;
    }

    _scanPollTimer?.cancel();

    setState(() {
      _isScanning = true;
      _scanRunStatus = 'queued';
      _scanScannedPorts = 0;
      _scanTotalPorts = 0;
      _scanPercent = 0;
      _activeScanJobId = null;
      _simulation = null;
      _lastScan = null;
    });

    try {
      final startResponse = await _client().startScan(
        target: target,
        scanType: _scanType,
        portRange: portRange,
        timeout: timeout,
      );

      if (!mounted) {
        return;
      }

      setState(() {
        _activeScanJobId = startResponse.jobId;
        _scanRunStatus = startResponse.status;
        _scanScannedPorts = startResponse.scannedPorts;
        _scanTotalPorts = startResponse.totalPorts;
        _scanPercent = startResponse.percent;
      });

      _beginScanPolling(startResponse.jobId);
    } on DioException catch (error) {
      _showError(_readDioError(error));
      if (mounted) {
        setState(() {
          _isScanning = false;
          _activeScanJobId = null;
          _scanRunStatus = 'failed';
        });
      }
    } catch (error) {
      _showError('Scan failed: $error');
      if (mounted) {
        setState(() {
          _isScanning = false;
          _activeScanJobId = null;
          _scanRunStatus = 'failed';
        });
      }
    }
  }

  void _beginScanPolling(String jobId) {
    _scanPollTimer?.cancel();
    _scanPollTimer = Timer.periodic(const Duration(milliseconds: 900), (_) {
      _refreshScanJob(jobId);
    });

    _refreshScanJob(jobId);
  }

  Future<void> _refreshScanJob(String jobId) async {
    if (_isPollingScan || !mounted) {
      return;
    }

    _isPollingScan = true;
    try {
      final statusPayload = await _client().getScanJobStatus(jobId);
      if (!mounted || _activeScanJobId != jobId) {
        return;
      }

      final scanSnapshot = statusPayload.toScanResponse();
      setState(() {
        _scanRunStatus = statusPayload.status;
        _scanScannedPorts = statusPayload.scannedPorts;
        _scanTotalPorts = statusPayload.totalPorts;
        _scanPercent = statusPayload.percent;
        _lastScan = scanSnapshot;
      });

      if (statusPayload.status == 'completed') {
        _scanPollTimer?.cancel();
        setState(() {
          _isScanning = false;
        });
        _showInfo(
          'Live scan completed with ${scanSnapshot.results.length} streamed port results using ${scanSnapshot.engine}.',
        );
      }

      if (statusPayload.status == 'failed') {
        _scanPollTimer?.cancel();
        setState(() {
          _isScanning = false;
        });
        _showError(statusPayload.error ?? 'Scan job failed.');
      }
    } on DioException catch (error) {
      if (!mounted || _activeScanJobId != jobId) {
        return;
      }

      _scanPollTimer?.cancel();
      setState(() {
        _isScanning = false;
        _scanRunStatus = 'failed';
      });
      _showError(_readDioError(error));
    } catch (error) {
      if (!mounted || _activeScanJobId != jobId) {
        return;
      }

      _scanPollTimer?.cancel();
      setState(() {
        _isScanning = false;
        _scanRunStatus = 'failed';
      });
      _showError('Failed while monitoring scan: $error');
    } finally {
      _isPollingScan = false;
    }
  }

  Future<void> _createRule() async {
    final sourceIp = _sourceIpController.text.trim();
    final portText = _rulePortController.text.trim();
    final priorityText = _priorityController.text.trim();

    final priority = int.tryParse(priorityText);
    if (priority == null || priority < 0) {
      _showError('Priority must be a positive integer.');
      return;
    }

    int? port;
    if (portText.isNotEmpty) {
      port = int.tryParse(portText);
      if (port == null || port < 1 || port > 65535) {
        _showError('Port must be between 1 and 65535.');
        return;
      }
    }

    final payload = <String, dynamic>{
      'action': _ruleAction,
      'protocol': _ruleProtocol,
      'priority': priority,
      'enabled': true,
      'note': _ruleNoteController.text.trim(),
    };

    if (sourceIp.isNotEmpty) {
      payload['source_ip'] = sourceIp;
    }

    if (port != null) {
      payload['port'] = port;
    }

    setState(() {
      _isSavingRule = true;
    });

    try {
      await _client().createFirewallRule(payload);
      _sourceIpController.clear();
      _rulePortController.clear();
      _ruleNoteController.clear();
      await _loadRules();
      _showInfo('Firewall rule added.');
    } on DioException catch (error) {
      _showError(_readDioError(error));
    } catch (error) {
      _showError('Failed to create rule: $error');
    } finally {
      if (mounted) {
        setState(() {
          _isSavingRule = false;
        });
      }
    }
  }

  Future<void> _deleteRule(int id) async {
    try {
      await _client().deleteFirewallRule(id);
      await _loadRules();
      _showInfo('Firewall rule deleted.');
    } on DioException catch (error) {
      _showError(_readDioError(error));
    } catch (error) {
      _showError('Failed to delete rule: $error');
    }
  }

  Future<void> _simulateTraffic() async {
    final scan = _lastScan;
    if (scan == null || scan.results.isEmpty) {
      _showError('Run a scan first to generate traffic flows.');
      return;
    }

    final simulationCandidates = scan.results
        .where(
          (entry) {
            final normalizedStatus = entry.status.toLowerCase();
            return normalizedStatus == 'open' ||
                normalizedStatus == 'open|filtered' ||
                normalizedStatus == 'filtered';
          },
        )
        .toList();

    if (simulationCandidates.isEmpty) {
      _showError('No open or filtered ports are available for simulation yet.');
      return;
    }

    final traffic = simulationCandidates
        .map(
          (entry) => {
            'ip': entry.ip,
            'port': entry.port,
            'protocol': entry.protocol,
            'status': entry.status.toLowerCase(),
          },
        )
        .toList();

    setState(() {
      _isSimulating = true;
    });

    try {
      final payload = await _client().simulateTraffic(traffic);
      if (!mounted) {
        return;
      }
      setState(() {
        _simulation = payload;
      });
    } on DioException catch (error) {
      _showError(_readDioError(error));
    } catch (error) {
      _showError('Simulation failed: $error');
    } finally {
      if (mounted) {
        setState(() {
          _isSimulating = false;
        });
      }
    }
  }

  void _showError(String message) {
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: const Color(0xFF922A2A),
      ),
    );
  }

  void _showInfo(String message) {
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: const Color(0xFF0B6A60),
      ),
    );
  }

  String _readDioError(DioException error) {
    final data = error.response?.data;
    if (data is Map && data['detail'] != null) {
      return data['detail'].toString();
    }
    if (data is Map) {
      return data.toString();
    }
    return error.message ?? 'Request failed.';
  }

  @override
  Widget build(BuildContext context) {
    final scanResults = _lastScan?.results ?? [];
    final simulation = _simulation;

    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              Color(0xFFDDEEE8),
              Color(0xFFF6F4EC),
              Color(0xFFE5ECF2),
            ],
          ),
        ),
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              return SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: ConstrainedBox(
                  constraints: BoxConstraints(minHeight: constraints.maxHeight - 32),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildHeader(),
                      const SizedBox(height: 16),
                      _panel(
                        title: 'Network Scanner',
                        subtitle: 'Target scanner using TCP SYN, UDP, or full TCP connect.',
                        icon: Icons.radar,
                        child: _buildScanSection(scanResults),
                      ),
                      const SizedBox(height: 16),
                      _panel(
                        title: 'Firewall Rule Simulator',
                        subtitle: 'Create allow/deny rules and evaluate traffic by priority.',
                        icon: Icons.shield,
                        child: _buildFirewallSection(),
                      ),
                      const SizedBox(height: 16),
                      _panel(
                        title: 'Traffic Flow Visualization',
                        subtitle: 'Visualize allowed and blocked traffic after rule chaining.',
                        icon: Icons.account_tree,
                        child: _buildSimulationSection(simulation),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 500),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF094641), Color(0xFF12776D)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(18),
        boxShadow: const [
          BoxShadow(
            color: Color(0x24000000),
            blurRadius: 14,
            offset: Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Network Security Scanner & Firewall Visualizer',
            style: TextStyle(
              color: Colors.white,
              fontSize: 24,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Django + Flutter desktop/web dashboard using Dio for API communication.',
            style: TextStyle(
              color: Colors.white.withValues(alpha: 0.9),
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  Widget _panel({
    required String title,
    required String subtitle,
    required IconData icon,
    required Widget child,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.88),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFFBFD2CF)),
        boxShadow: const [
          BoxShadow(
            color: Color(0x14000000),
            blurRadius: 10,
            offset: Offset(0, 6),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: const Color(0xFF0D5A52)),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w700),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(subtitle, style: const TextStyle(color: Color(0xFF394948))),
          const SizedBox(height: 16),
          child,
        ],
      ),
    );
  }

  Widget _buildScanSection(List<ScanResultItem> scanResults) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _inputField(
              controller: _baseUrlController,
              label: 'API Base URL',
              width: 340,
            ),
            _inputField(
              controller: _targetController,
              label: 'Target IP / Hostname',
              width: 240,
            ),
            _inputField(
              controller: _portRangeController,
              label: 'Port Range',
              width: 200,
              hint: 'e.g. 20-1024,3306',
            ),
            _inputField(
              controller: _timeoutController,
              label: 'Timeout (seconds)',
              width: 160,
            ),
            SizedBox(
              width: 190,
              child: DropdownButtonFormField<String>(
                initialValue: _scanType,
                isExpanded: true,
                decoration: const InputDecoration(
                  labelText: 'Scan Type',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                items: const [
                  DropdownMenuItem(value: 'tcp_syn', child: Text('TCP SYN')),
                  DropdownMenuItem(value: 'udp', child: Text('UDP')),
                  DropdownMenuItem(value: 'full_connect', child: Text('Full Connect')),
                ],
                onChanged: (value) {
                  if (value == null) {
                    return;
                  }
                  setState(() {
                    _scanType = value;
                  });
                },
              ),
            ),
            FilledButton.icon(
              onPressed: _isScanning ? null : _startScan,
              icon: _isScanning
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: Text(_isScanning ? 'Monitoring...' : 'Start Live Scan'),
            ),
          ],
        ),
        const SizedBox(height: 14),
        if (_activeScanJobId != null) ...[
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _chip('Job: $_activeScanJobId'),
              _chip('Status: ${_scanRunStatus.toUpperCase()}'),
              _chip('Progress: ${_scanScannedPorts.toString()}/${_scanTotalPorts.toString()}'),
              _chip('${_scanPercent.toStringAsFixed(2)}%'),
            ],
          ),
          const SizedBox(height: 8),
          LinearProgressIndicator(
            value: _scanTotalPorts > 0 ? _scanScannedPorts / _scanTotalPorts : null,
            minHeight: 8,
            borderRadius: BorderRadius.circular(999),
            backgroundColor: const Color(0xFFE7EFED),
          ),
          const SizedBox(height: 6),
          Text(
            _scanRunStatus == 'completed'
                ? 'Live monitoring complete.'
                : 'Live monitoring in progress. Results stream in as ports are scanned.',
            style: const TextStyle(color: Color(0xFF2D4C47)),
          ),
          const SizedBox(height: 12),
        ],
        if (_lastScan != null)
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _chip('Engine: ${_lastScan!.engine}'),
              _chip('Target: ${_lastScan!.target}'),
              _chip('Resolved IP: ${_lastScan!.resolvedIp}'),
              _chip('Ports scanned: ${_lastScan!.portCount}'),
              _chip('Results streamed: ${_lastScan!.results.length}'),
            ],
          ),
        const SizedBox(height: 14),
        const Text(
          'Live Port Results',
          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
        ),
        const SizedBox(height: 8),
        if (scanResults.isEmpty)
          Text(
            _isScanning
                ? 'No port results yet. Rows will appear as each port is scanned.'
                : 'No scan results yet. Run a scan to populate this table.',
          )
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columnSpacing: 20,
              columns: const [
                DataColumn(label: Text('IP')),
                DataColumn(label: Text('Port')),
                DataColumn(label: Text('Protocol')),
                DataColumn(label: Text('Verified Service')),
                DataColumn(label: Text('Status')),
              ],
              rows: scanResults
                  .map(
                    (row) => DataRow(
                      cells: [
                        DataCell(Text(row.ip)),
                        DataCell(Text(row.port.toString())),
                        DataCell(Text(row.protocol.toUpperCase())),
                        DataCell(Text(row.service)),
                        DataCell(Text(row.status)),
                      ],
                    ),
                  )
                  .toList(),
            ),
          ),
      ],
    );
  }

  Widget _buildFirewallSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            SizedBox(
              width: 140,
              child: DropdownButtonFormField<String>(
                initialValue: _ruleAction,
                isExpanded: true,
                decoration: const InputDecoration(
                  labelText: 'Action',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                items: const [
                  DropdownMenuItem(value: 'allow', child: Text('Allow')),
                  DropdownMenuItem(value: 'deny', child: Text('Deny')),
                ],
                onChanged: (value) {
                  if (value == null) {
                    return;
                  }
                  setState(() {
                    _ruleAction = value;
                  });
                },
              ),
            ),
            SizedBox(
              width: 140,
              child: DropdownButtonFormField<String>(
                initialValue: _ruleProtocol,
                isExpanded: true,
                decoration: const InputDecoration(
                  labelText: 'Protocol',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                items: const [
                  DropdownMenuItem(value: 'any', child: Text('Any')),
                  DropdownMenuItem(value: 'tcp', child: Text('TCP')),
                  DropdownMenuItem(value: 'udp', child: Text('UDP')),
                ],
                onChanged: (value) {
                  if (value == null) {
                    return;
                  }
                  setState(() {
                    _ruleProtocol = value;
                  });
                },
              ),
            ),
            _inputField(
              controller: _sourceIpController,
              label: 'Source IP (optional)',
              width: 220,
              hint: 'blank = any',
            ),
            _inputField(
              controller: _rulePortController,
              label: 'Port (optional)',
              width: 160,
            ),
            _inputField(
              controller: _priorityController,
              label: 'Priority',
              width: 120,
            ),
            _inputField(
              controller: _ruleNoteController,
              label: 'Note',
              width: 220,
            ),
            FilledButton.icon(
              onPressed: _isSavingRule ? null : _createRule,
              icon: _isSavingRule
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.add),
              label: Text(_isSavingRule ? 'Saving...' : 'Add Rule'),
            ),
            OutlinedButton.icon(
              onPressed: _isLoadingRules ? null : _loadRules,
              icon: const Icon(Icons.refresh),
              label: const Text('Reload Rules'),
            ),
          ],
        ),
        const SizedBox(height: 14),
        const Text(
          'Firewall Rule Chain (ordered by priority)',
          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
        ),
        const SizedBox(height: 8),
        if (_isLoadingRules)
          const LinearProgressIndicator()
        else if (_rules.isEmpty)
          const Text('No firewall rules defined yet.')
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columnSpacing: 18,
              columns: const [
                DataColumn(label: Text('Priority')),
                DataColumn(label: Text('Action')),
                DataColumn(label: Text('Protocol')),
                DataColumn(label: Text('Source IP')),
                DataColumn(label: Text('Port')),
                DataColumn(label: Text('Note')),
                DataColumn(label: Text('Delete')),
              ],
              rows: _rules
                  .map(
                    (rule) => DataRow(
                      cells: [
                        DataCell(Text(rule.priority.toString())),
                        DataCell(Text(rule.action.toUpperCase())),
                        DataCell(Text(rule.protocol.toUpperCase())),
                        DataCell(Text(rule.sourceIp ?? 'any')),
                        DataCell(Text(rule.port?.toString() ?? 'any')),
                        DataCell(Text(rule.note.isEmpty ? '-' : rule.note)),
                        DataCell(
                          IconButton(
                            icon: const Icon(Icons.delete_outline),
                            tooltip: 'Delete rule',
                            onPressed: () => _deleteRule(rule.id),
                          ),
                        ),
                      ],
                    ),
                  )
                  .toList(),
            ),
          ),
      ],
    );
  }

  Widget _buildSimulationSection(SimulationPayload? simulation) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            FilledButton.icon(
              onPressed: _isSimulating ? null : _simulateTraffic,
              icon: _isSimulating
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.timeline),
              label: Text(_isSimulating ? 'Simulating...' : 'Run Simulation'),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Text(
                'Simulation uses scan results as traffic inputs and applies firewall rules from top priority to bottom.',
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (simulation == null)
          const Text('No simulation yet. Run a scan, then run simulation.')
        else ...[
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              _summaryCard(
                title: 'Total Flows',
                value: simulation.total.toString(),
                color: const Color(0xFF0B5E55),
              ),
              _summaryCard(
                title: 'Allowed',
                value: simulation.allowed.toString(),
                color: const Color(0xFF2B8A3E),
              ),
              _summaryCard(
                title: 'Blocked',
                value: simulation.blocked.toString(),
                color: const Color(0xFFAA3A31),
              ),
            ],
          ),
          const SizedBox(height: 14),
          TrafficFlowDiagram(
            total: simulation.total,
            allowed: simulation.allowed,
            blocked: simulation.blocked,
          ),
          const SizedBox(height: 14),
          const Text(
            'Flow Decisions',
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
          ),
          const SizedBox(height: 8),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columnSpacing: 20,
              columns: const [
                DataColumn(label: Text('IP')),
                DataColumn(label: Text('Port')),
                DataColumn(label: Text('Protocol')),
                DataColumn(label: Text('Scan Status')),
                DataColumn(label: Text('Decision')),
                DataColumn(label: Text('Matched Rule')),
              ],
              rows: simulation.flows
                  .map(
                    (flow) => DataRow(
                      cells: [
                        DataCell(Text(flow.ip)),
                        DataCell(Text(flow.port.toString())),
                        DataCell(Text(flow.protocol.toUpperCase())),
                        DataCell(Text(flow.scanStatus.toUpperCase())),
                        DataCell(
                          Text(
                            flow.decision.toUpperCase(),
                            style: TextStyle(
                              color: flow.decision == 'allow'
                                  ? const Color(0xFF1E7A33)
                                  : const Color(0xFFAF2E2E),
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        DataCell(Text(flow.matchedRuleId?.toString() ?? 'default deny')),
                      ],
                    ),
                  )
                  .toList(),
            ),
          ),
        ],
      ],
    );
  }

  Widget _inputField({
    required TextEditingController controller,
    required String label,
    double width = 220,
    String? hint,
  }) {
    return SizedBox(
      width: width,
      child: TextField(
        controller: controller,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }

  Widget _chip(String text) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0xFFE0EBE8),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(text),
    );
  }

  Widget _summaryCard({required String title, required String value, required Color color}) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 350),
      width: 170,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: TextStyle(color: color, fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          Text(
            value,
            style: TextStyle(color: color, fontWeight: FontWeight.w800, fontSize: 24),
          ),
        ],
      ),
    );
  }
}

class TrafficFlowDiagram extends StatelessWidget {
  final int total;
  final int allowed;
  final int blocked;

  const TrafficFlowDiagram({
    super.key,
    required this.total,
    required this.allowed,
    required this.blocked,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFFF8FBFA),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFFCAD9D6)),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Expanded(
                child: _node(
                  title: 'Incoming Traffic',
                  subtitle: '$total packets',
                  color: const Color(0xFF3D5C7A),
                  icon: Icons.input,
                ),
              ),
              const Padding(
                padding: EdgeInsets.symmetric(horizontal: 8),
                child: Icon(Icons.arrow_forward, color: Color(0xFF5D6D70)),
              ),
              Expanded(
                child: _node(
                  title: 'Rule Chain',
                  subtitle: 'priority order',
                  color: const Color(0xFF0D6C61),
                  icon: Icons.rule,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              const Expanded(child: SizedBox()),
              const Expanded(
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: EdgeInsets.only(left: 12),
                    child: Icon(Icons.call_split, color: Color(0xFF5D6D70)),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _node(
                  title: 'Allowed',
                  subtitle: '$allowed flows',
                  color: const Color(0xFF2F8D40),
                  icon: Icons.check_circle_outline,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _node(
                  title: 'Blocked',
                  subtitle: '$blocked flows',
                  color: const Color(0xFFB03A2E),
                  icon: Icons.block,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _node({
    required String title,
    required String subtitle,
    required Color color,
    required IconData icon,
  }) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 350),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(fontWeight: FontWeight.w700, color: color),
                ),
                Text(subtitle, style: const TextStyle(fontSize: 12)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class BackendApiClient {
  final Dio _dio;

  BackendApiClient({required String baseUrl})
      : _dio = Dio(
          BaseOptions(
            baseUrl: baseUrl,
            connectTimeout: const Duration(seconds: 10),
            receiveTimeout: const Duration(seconds: 60),
            sendTimeout: const Duration(seconds: 10),
            headers: {
              'Content-Type': 'application/json',
            },
          ),
        );

  Future<List<FirewallRuleItem>> listFirewallRules() async {
    final response = await _dio.get('/firewall/rules/');
    final data = response.data as List<dynamic>;
    return data
        .map((item) => FirewallRuleItem.fromJson(Map<String, dynamic>.from(item as Map)))
        .toList();
  }

  Future<void> createFirewallRule(Map<String, dynamic> payload) async {
    await _dio.post('/firewall/rules/', data: payload);
  }

  Future<void> deleteFirewallRule(int id) async {
    await _dio.delete('/firewall/rules/$id/');
  }

  Future<ScanJobStartPayload> startScan({
    required String target,
    required String scanType,
    required String portRange,
    required double timeout,
  }) async {
    final response = await _dio.post(
      '/scan/start/',
      data: {
        'target': target,
        'scan_type': scanType,
        'port_range': portRange,
        'timeout': timeout,
      },
    );

    return ScanJobStartPayload.fromJson(Map<String, dynamic>.from(response.data as Map));
  }

  Future<ScanJobStatusPayload> getScanJobStatus(String jobId) async {
    final response = await _dio.get('/scan/jobs/$jobId/');
    return ScanJobStatusPayload.fromJson(Map<String, dynamic>.from(response.data as Map));
  }

  Future<SimulationPayload> simulateTraffic(List<Map<String, dynamic>> traffic) async {
    final response = await _dio.post(
      '/firewall/simulate/',
      data: {'traffic': traffic},
    );

    return SimulationPayload.fromJson(Map<String, dynamic>.from(response.data as Map));
  }
}

class ScanJobStartPayload {
  final String jobId;
  final String status;
  final int scannedPorts;
  final int totalPorts;
  final double percent;

  ScanJobStartPayload({
    required this.jobId,
    required this.status,
    required this.scannedPorts,
    required this.totalPorts,
    required this.percent,
  });

  factory ScanJobStartPayload.fromJson(Map<String, dynamic> json) {
    final progress = Map<String, dynamic>.from(json['progress'] as Map? ?? {});
    return ScanJobStartPayload(
      jobId: json['job_id']?.toString() ?? '',
      status: json['status']?.toString() ?? 'queued',
      scannedPorts: (progress['scanned_ports'] as num?)?.toInt() ?? 0,
      totalPorts: (progress['total_ports'] as num?)?.toInt() ?? 0,
      percent: (progress['percent'] as num?)?.toDouble() ?? 0,
    );
  }
}

class ScanJobStatusPayload {
  final String jobId;
  final String status;
  final String target;
  final String resolvedIp;
  final String scanType;
  final String engine;
  final int portCount;
  final int scannedPorts;
  final int totalPorts;
  final double percent;
  final List<ScanResultItem> results;
  final String? error;

  ScanJobStatusPayload({
    required this.jobId,
    required this.status,
    required this.target,
    required this.resolvedIp,
    required this.scanType,
    required this.engine,
    required this.portCount,
    required this.scannedPorts,
    required this.totalPorts,
    required this.percent,
    required this.results,
    required this.error,
  });

  factory ScanJobStatusPayload.fromJson(Map<String, dynamic> json) {
    final progress = Map<String, dynamic>.from(json['progress'] as Map? ?? {});
    final resultList = json['results'] as List<dynamic>? ?? [];

    return ScanJobStatusPayload(
      jobId: json['job_id']?.toString() ?? '',
      status: json['status']?.toString() ?? 'running',
      target: json['target']?.toString() ?? '',
      resolvedIp: json['resolved_ip']?.toString() ?? '',
      scanType: json['scan_type']?.toString() ?? '',
      engine: json['engine']?.toString() ?? 'unknown',
      portCount: (json['port_count'] as num?)?.toInt() ?? 0,
      scannedPorts: (progress['scanned_ports'] as num?)?.toInt() ?? 0,
      totalPorts: (progress['total_ports'] as num?)?.toInt() ?? 0,
      percent: (progress['percent'] as num?)?.toDouble() ?? 0,
      results: resultList
          .map((item) => ScanResultItem.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(),
      error: json['error']?.toString(),
    );
  }

  ScanResponsePayload toScanResponse() {
    return ScanResponsePayload(
      target: target,
      resolvedIp: resolvedIp,
      scanType: scanType,
      engine: engine,
      portCount: portCount,
      results: results,
    );
  }
}

class ScanResponsePayload {
  final String target;
  final String resolvedIp;
  final String scanType;
  final String engine;
  final int portCount;
  final List<ScanResultItem> results;

  ScanResponsePayload({
    required this.target,
    required this.resolvedIp,
    required this.scanType,
    required this.engine,
    required this.portCount,
    required this.results,
  });

  factory ScanResponsePayload.fromJson(Map<String, dynamic> json) {
    final resultList = json['results'] as List<dynamic>? ?? [];
    return ScanResponsePayload(
      target: json['target']?.toString() ?? '',
      resolvedIp: json['resolved_ip']?.toString() ?? '',
      scanType: json['scan_type']?.toString() ?? '',
      engine: json['engine']?.toString() ?? 'unknown',
      portCount: (json['port_count'] as num?)?.toInt() ?? 0,
      results: resultList
          .map((item) => ScanResultItem.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(),
    );
  }
}

class ScanResultItem {
  final String ip;
  final int port;
  final String protocol;
  final String service;
  final String status;

  ScanResultItem({
    required this.ip,
    required this.port,
    required this.protocol,
    required this.service,
    required this.status,
  });

  factory ScanResultItem.fromJson(Map<String, dynamic> json) {
    return ScanResultItem(
      ip: json['ip']?.toString() ?? '',
      port: (json['port'] as num?)?.toInt() ?? 0,
      protocol: json['protocol']?.toString() ?? 'unknown',
      service: json['service']?.toString() ?? 'unknown',
      status: json['status']?.toString() ?? 'unknown',
    );
  }
}

class FirewallRuleItem {
  final int id;
  final String action;
  final String? sourceIp;
  final int? port;
  final String protocol;
  final int priority;
  final bool enabled;
  final String note;

  FirewallRuleItem({
    required this.id,
    required this.action,
    required this.sourceIp,
    required this.port,
    required this.protocol,
    required this.priority,
    required this.enabled,
    required this.note,
  });

  factory FirewallRuleItem.fromJson(Map<String, dynamic> json) {
    return FirewallRuleItem(
      id: (json['id'] as num?)?.toInt() ?? 0,
      action: json['action']?.toString() ?? 'deny',
      sourceIp: json['source_ip']?.toString(),
      port: (json['port'] as num?)?.toInt(),
      protocol: json['protocol']?.toString() ?? 'any',
      priority: (json['priority'] as num?)?.toInt() ?? 100,
      enabled: json['enabled'] as bool? ?? true,
      note: json['note']?.toString() ?? '',
    );
  }
}

class SimulationPayload {
  final int total;
  final int allowed;
  final int blocked;
  final List<SimulationFlowItem> flows;

  SimulationPayload({
    required this.total,
    required this.allowed,
    required this.blocked,
    required this.flows,
  });

  factory SimulationPayload.fromJson(Map<String, dynamic> json) {
    final summary = Map<String, dynamic>.from(json['summary'] as Map? ?? {});
    final flowList = json['flows'] as List<dynamic>? ?? [];

    return SimulationPayload(
      total: (summary['total'] as num?)?.toInt() ?? 0,
      allowed: (summary['allowed'] as num?)?.toInt() ?? 0,
      blocked: (summary['blocked'] as num?)?.toInt() ?? 0,
      flows: flowList
          .map((item) => SimulationFlowItem.fromJson(Map<String, dynamic>.from(item as Map)))
          .toList(),
    );
  }
}

class SimulationFlowItem {
  final String ip;
  final int port;
  final String protocol;
  final String scanStatus;
  final String decision;
  final int? matchedRuleId;

  SimulationFlowItem({
    required this.ip,
    required this.port,
    required this.protocol,
    required this.scanStatus,
    required this.decision,
    required this.matchedRuleId,
  });

  factory SimulationFlowItem.fromJson(Map<String, dynamic> json) {
    final matchedRule = json['matched_rule'];
    int? matchedRuleId;
    if (matchedRule is Map && matchedRule['id'] != null) {
      matchedRuleId = (matchedRule['id'] as num?)?.toInt();
    }

    return SimulationFlowItem(
      ip: json['ip']?.toString() ?? '',
      port: (json['port'] as num?)?.toInt() ?? 0,
      protocol: json['protocol']?.toString() ?? 'unknown',
      scanStatus: json['scan_status']?.toString() ?? 'unknown',
      decision: json['decision']?.toString() ?? 'deny',
      matchedRuleId: matchedRuleId,
    );
  }
}
