import 'dart:async';

/// Tells the app root that a Cloudflare Access session expired mid-use.
///
/// A burst of failing requests is one episode: [report] emits a single event
/// until [resolve] closes it, so the UI shows one dialog, not one per request.
class CfExpiryNotifier {
  final StreamController<String> _controller = StreamController.broadcast();
  bool _open = false;

  /// Hosts whose session expired, one event per episode.
  Stream<String> get events => _controller.stream;

  /// True between an emitted event and [resolve].
  bool get episodeOpen => _open;

  void report(String host) {
    if (_open) return;
    _open = true;
    _controller.add(host);
  }

  /// Closes the current episode so the next failure can be reported.
  void resolve() => _open = false;
}
