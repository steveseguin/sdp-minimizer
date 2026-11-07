var test = require('tape');
var min = require('../');

var foundations = [
  '0', '9', 'a', '10', '31', '1234567890', 'alpha', 'a1b', 'ab1', '+abc/DEFG',
  'abcdefghijklmnopqrstuvwxyz012345'
];
for (var length = 1; length <= 32; length++) {
  foundations.push(Array(length + 1).join('f'));
}
var fingerprint = '01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:' +
  '01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF';

function description(candidates, type) {
  return {
    type: type || 'offer',
    sdp: [
      'v=0',
      'a=ice-ufrag:abcdefgh',
      'a=ice-pwd:abcdefghijklmnopqrstuvwx',
      'a=fingerprint:sha-256 ' + fingerprint
    ].concat(candidates).join('\r\n') + '\r\n'
  };
}

function candidate(foundation, component, port, type) {
  return 'a=candidate:' + foundation + ' ' + component +
    ' udp 1677729535 203.0.113.7 ' + port + ' typ ' + (type || 'relay') +
    ' raddr 192.0.2.1 rport 40000';
}

function expandedCandidates(compact) {
  return min.expand(compact).sdp.split('\r\n').filter(function (line) {
    return line.indexOf('a=candidate:') === 0;
  });
}

test('component 1 relay candidates survive every legal foundation length', function (t) {
  foundations.forEach(function (foundation) {
    var compact = min.reduce(description([candidate(foundation, 1, 50000)]));
    t.equal(compact.split(',').length, 6, foundation + ': address and port retained');
    t.deepEqual(expandedCandidates(compact), [
      'a=candidate:0 1 udp 1 203.0.113.7 50000 typ host'
    ], foundation + ': relay address and port round-trip');
  });
  t.end();
});

test('component 2 is excluded even when a foundation contains 1', function (t) {
  var noCandidates = min.reduce(description([]));
  foundations.forEach(function (foundation) {
    t.equal(min.reduce(description([candidate(foundation, 2, 50001)])),
      noCandidates, foundation + ': component 2 excluded');
  });
  t.end();
});

test('mixed components retain only the component 1 endpoint', function (t) {
  var compact = min.reduce(description([
    candidate('ab1', 2, 50001),
    candidate('10', 1, 50000)
  ], 'answer'));
  t.equal(min.expand(compact).type, 'answer');
  t.deepEqual(expandedCandidates(compact), [
    'a=candidate:0 1 udp 1 203.0.113.7 50000 typ host'
  ]);
  t.end();
});

test('existing host and server-reflexive filtering is unchanged', function (t) {
  t.equal(min.reduce(description([
    candidate('10', 1, 50000, 'host'),
    candidate('10', 1, 50001, 'srflx')
  ])), min.reduce(description([])));
  t.end();
});

test('multiple component 1 ports on one relay address are retained', function (t) {
  var candidates = expandedCandidates(min.reduce(description([
    candidate('10', 1, 50000),
    candidate('31', 1, 50002)
  ])));
  var endpoints = candidates.map(function (line) {
    return line.split(' ').slice(4, 6).join(':');
  }).sort();
  t.deepEqual(endpoints, ['203.0.113.7:50000', '203.0.113.7:50002']);
  t.end();
});
