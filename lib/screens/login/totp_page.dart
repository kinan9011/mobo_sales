import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:hugeicons/hugeicons.dart';
import 'package:loading_animation_widget/loading_animation_widget.dart';
import 'package:provider/provider.dart';
import '../../services/auth_service.dart';
import '../../services/cf_access/cf_access_gate.dart';
import '../../services/odoo_session_manager.dart';
import '../../services/odoo_totp_login.dart';
import '../../services/shared_http.dart';
import '../../services/session_service.dart';
import '../../home_scaffold.dart';

class TotpPage extends StatefulWidget {
  final String serverUrl;
  final String database;
  final String username;
  final String password;
  final String protocol;
  final bool isAddingAccount;

  const TotpPage({
    super.key,
    required this.serverUrl,
    required this.database,
    required this.username,
    required this.password,
    required this.protocol,
    this.isAddingAccount = false,
  });

  @override
  State<TotpPage> createState() => _TotpPageState();
}

class _TotpPageState extends State<TotpPage> {
  final _totpController = TextEditingController();
  String? _error;
  bool _loading = true;
  bool _verifying = false;
  bool _isButtonEnabled = false;
  final _formKey = GlobalKey<FormState>();
  bool _isSessionExtracted = false;
  bool _loginSuccess = false;

  late final OdooTotpLogin _login;
  late final CfAccessGate _gate;
  late final Uri _server;

  @override
  void initState() {
    super.initState();
    _server = Uri.parse(widget.serverUrl);
    _gate = CfAccessGate(SharedHttp.auth);
    _login = OdooTotpLogin(
      client: OdooSessionManager.ioClient,
      serverUrl: widget.serverUrl,
      database: widget.database,
      userAgent: OdooSessionManager.USER_AGENT,
    );
    _start();
  }

  @override
  void dispose() {
    _totpController.dispose();
    super.dispose();
  }

  /// Submits the credentials so Odoo hands out the TOTP form.
  Future<TotpLoginResult> _startLogin() => _gate.guard(
    _server,
    () => _login.start(widget.username, widget.password),
  );

  Future<void> _start() async {
    try {
      await _apply(await _startLogin());
    } on CfGateException catch (e) {
      _fail(e.message);
    } catch (_) {
      _fail('Failed to load. Please check your connection and try again.');
    }
  }

  void _fail(String message) {
    if (!mounted) return;
    setState(() {
      _loading = false;
      _verifying = false;
      _error = message;
    });
  }

  Future<void> _apply(TotpLoginResult result) async {
    switch (result) {
      case TotpCodeRequired():
        if (mounted) setState(() => _loading = false);
      case TotpLoginFailed(:final message):
        _fail(message);
      case TotpLoginSuccess(:final sessionId):
        await _saveSessionData(sessionId);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      body: Stack(
        children: [
          Positioned.fill(
            child: Container(
              decoration: BoxDecoration(
                color: isDark ? Colors.grey[950] : Colors.grey[50],
                image: DecorationImage(
                  image: const AssetImage('assets/login_background.png'),
                  fit: BoxFit.cover,
                  colorFilter: ColorFilter.mode(
                    isDark
                        ? Colors.black.withOpacity(1)
                        : Colors.white.withOpacity(1),
                    BlendMode.dstATop,
                  ),
                ),
              ),
            ),
          ),

          Positioned(
            top: 0,
            left: 0,
            child: SafeArea(
              bottom: false,
              child: IgnorePointer(
                ignoring: _loading,
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    onTap: () => Navigator.of(context).pop(),
                    borderRadius: BorderRadius.circular(32),
                    child: Container(
                      height: 64,
                      width: 64,
                      alignment: Alignment.center,
                      child: HugeIcon(
                        icon: HugeIcons.strokeRoundedArrowLeft01,
                        color: _loading ? Colors.white54 : Colors.white,
                        size: 24,
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),

          Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _buildHeader(),
                const SizedBox(height: 20),
                _buildForm(),
              ],
            ),
          ),

          if (_loading)
            Container(
              color: Colors.white70,
              child: Center(
                child: LoadingAnimationWidget.fourRotatingDots(
                  color: Theme.of(context).colorScheme.primary,
                  size: 60,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      children: [
        const HugeIcon(
          icon: HugeIcons.strokeRoundedTwoFactorAccess,
          color: Colors.white,
          size: 48,
        ),
        const SizedBox(height: 24),
        Text(
          'Two-factor Authentication',
          style: GoogleFonts.montserrat(
            fontWeight: FontWeight.w600,
            color: Colors.white,
            fontSize: 25,
          ),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        Text(
          'To login, enter below the six-digit authentication code provided by your Authenticator app.',
          style: GoogleFonts.montserrat(
            fontSize: 14,
            color: Colors.white70,
            height: 1.4,
          ),
          textAlign: TextAlign.center,
        ),
        if (widget.serverUrl.isNotEmpty) ...[
          const SizedBox(height: 16),
          Text(
            'Server: ${widget.serverUrl}',
            style: GoogleFonts.manrope(
              fontSize: 12,
              color: Colors.white60,
              fontWeight: FontWeight.w500,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ],
    );
  }

  Widget _buildForm() {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextFormField(
            controller: _totpController,
            keyboardType: TextInputType.number,
            enabled: !_loading && !_verifying,
            validator: (value) {
              if (value == null || value.trim().isEmpty) {
                return 'TOTP is required';
              }
              return null;
            },
            onChanged: (value) {
              setState(() {
                _isButtonEnabled = value.trim().isNotEmpty;
                _formKey.currentState?.validate();
                if (_error != null) _error = null;
              });
            },
            cursorColor: Colors.black,
            style: GoogleFonts.manrope(
              fontSize: 14,
              fontWeight: FontWeight.w400,
              color: Colors.black,
            ),
            decoration: InputDecoration(
              hintText: 'Enter TOTP Code',
              hintStyle: GoogleFonts.manrope(
                fontSize: 14,
                fontWeight: FontWeight.w400,
                color: Colors.black.withValues(alpha: 0.4),
              ),
              prefixIcon: SizedBox(
                width: 48,
                height: 48,
                child: Center(
                  child: Transform.scale(
                    scale: 20 / 24.0,
                    child: const HugeIcon(
                      icon: HugeIcons.strokeRoundedSmsCode,
                      color: Colors.black54,
                      size: 24,
                    ),
                  ),
                ),
              ),
              prefixIconColor: WidgetStateColor.resolveWith(
                (states) => states.contains(WidgetState.disabled)
                    ? Colors.black26
                    : Colors.black54,
              ),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide.none,
              ),
              filled: true,
              fillColor: Colors.white,
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 20,
                vertical: 16,
              ),
              errorStyle: const TextStyle(color: Colors.white),
              errorBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide(color: Colors.red[900]!, width: 1.0),
              ),
              focusedErrorBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: const BorderSide(color: Colors.white, width: 1.5),
              ),
            ),
          ),
          const SizedBox(height: 10),

          AnimatedContainer(
            duration: const Duration(milliseconds: 300),
            height: _error == null ? 0 : (_error!.contains('\n') ? 120 : 48),
            child: _error != null
                ? Padding(
                    padding: const EdgeInsets.only(bottom: 8.0),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        const HugeIcon(
                          icon: HugeIcons.strokeRoundedAlertCircle,
                          color: Colors.white,
                          size: 18,
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _error!,
                            style: GoogleFonts.manrope(
                              color: Colors.white,
                              fontSize: 12,
                              fontWeight: FontWeight.w400,
                            ),
                          ),
                        ),
                      ],
                    ),
                  )
                : null,
          ),

          const SizedBox(height: 20),

          SizedBox(
            height: 48,
            child: ElevatedButton(
              onPressed: (_verifying || !_isButtonEnabled) ? null : _submitTotp,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.black,
                foregroundColor: Colors.white,
                disabledForegroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              child: _verifying
                  ? Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          'Authenticating',
                          style: GoogleFonts.manrope(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(width: 12),
                        LoadingAnimationWidget.staggeredDotsWave(
                          color: Colors.white,
                          size: 28,
                        ),
                      ],
                    )
                  : Text(
                      'Authenticate',
                      style: GoogleFonts.manrope(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _submitTotp() async {
    if (_verifying) return;

    setState(() {
      _verifying = true;
      _error = null;
    });

    final totp = _totpController.text.trim();
    if (totp.length != 6 || !RegExp(r'^\d{6}$').hasMatch(totp)) {
      setState(() {
        _error = 'Please enter a valid 6-digit code';
        _verifying = false;
      });
      return;
    }

    try {
      // A failed first step (e.g. no network at open) is redone here.
      if (!_login.awaitingCode) {
        final started = await _startLogin();
        if (started is! TotpCodeRequired) {
          await _apply(started);
          return;
        }
      }
      await _apply(await _gate.guard(_server, () => _login.submitCode(totp)));
    } on CfGateException catch (e) {
      _fail(e.message);
    } catch (e) {
      _fail('Authentication failed. Please try again.');
    } finally {
      if (mounted && !_loginSuccess) {
        setState(() {
          _verifying = false;
        });
      }
    }
  }

  Future<void> _onLoginSuccess() async {
    if (!mounted) return;

    setState(() {
      _loginSuccess = true;
      _verifying = true;
    });

    try {
      final session = await OdooSessionManager.getCurrentSession();
      if (!mounted) return;

      if (session != null) {
        final sessionService = Provider.of<SessionService>(
          context,
          listen: false,
        );

        if (widget.isAddingAccount) {
          Navigator.pop(context, true);
          return;
        }

        await sessionService.switchToAccount(session);

        if (!mounted) return;
        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (context) => const HomeScaffold()),
          (route) => false,
        );
      } else {
        if (widget.isAddingAccount) {
          Navigator.pop(context, true);
        } else {
          Navigator.pushAndRemoveUntil(
            context,
            MaterialPageRoute(builder: (context) => const HomeScaffold()),
            (route) => false,
          );
        }
      }
    } catch (_) {
      if (!mounted) return;

      if (widget.isAddingAccount) {
        Navigator.pop(context, true);
      } else {
        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (context) => const HomeScaffold()),
          (route) => false,
        );
      }
    }
  }

  /// Hands the Odoo `session_id` to the regular session setup.
  Future<void> _saveSessionData(String sessionId) async {
    if (_isSessionExtracted) return;

    try {
      final success = await _gate.guard(
        _server,
        () => AuthService().loginWithSessionId(
          serverUrl: widget.serverUrl,
          database: widget.database,
          userLogin: widget.username.trim(),
          password: widget.password.trim(),
          sessionId: sessionId,
        ),
      );
      if (success) {
        _isSessionExtracted = true;
        await _onLoginSuccess();
      } else {
        _fail('Code accepted, but loading your Odoo session failed.');
      }
    } on CfGateException catch (e) {
      _fail(e.message);
    } catch (e) {
      debugPrint('[TotpPage] session handoff failed: $e');
      _fail('Invalid code or login failed. Please try again.');
    }
  }
}
