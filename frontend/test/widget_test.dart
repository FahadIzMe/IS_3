// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';

import 'package:frontend/main.dart';

void main() {
  testWidgets('Scanner screen renders', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: ScannerHomePage(autoLoadRules: false),
      ),
    );

    expect(find.text('Network Security Scanner & Firewall Visualizer'), findsOneWidget);
    expect(find.text('Network Scanner'), findsOneWidget);
    expect(find.text('Firewall Rule Simulator'), findsOneWidget);
  });
}
