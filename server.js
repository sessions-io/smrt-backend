var async = require('async');
var bcrypt = require('bcrypt');
var express = require('express');
var http = require('http');
var r = require('rethinkdb');
var request = require('request');
var redis = require('redis');
var bodyParser = require('body-parser');
var session = require('express-session')
var RedisStore = require('connect-redis')(session);
var apn = require('apn');
var fs = require('fs');
var uuid = require('node-uuid');

// load the push notification cert and key
var challengeCert = new Buffer(process.env.CHALLENGE_APN_CERT, 'base64');
challengeCert = challengeCert.toString();
var challengeKey = new Buffer(process.env.CHALLENGE_APN_KEY, 'base64');
challengeKey = challengeKey.toString();
var apnEnvironment = process.env.APN_ENV;

// connection to APN server
var challengeAPN = new apn.Connection({
  cert: new Buffer(challengeCert),
  key: new Buffer(challengeKey),
  production: apnEnvironment == 'production' ? true : false
});

// actively check for delivery failures and cleanup db
var challengeAPNFeedback = new apn.Feedback( {
  cert: new Buffer(challengeCert),
  key: new Buffer(challengeKey),
  production: apnEnvironment == 'production' ? true : false,
  batchFeedback: true,
  interval: 300
});

// manage mobile notification tokens
r.connect({
  host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
  port: process.env.USERSTORE_PORT_28015_TCP_PORT
}, function (err, conn) {

  if (err) {
    console.log('interval cant connect to rethink');
    return;
  }

  // listen for changes from the APN database that indicate delivery failure (app uninstalls?)
  challengeAPNFeedback.on('feedback', function(devices) {
      devices.forEach(function(item) {
        var failTime = new Date(0);
        failTime.setUTCSeconds(item.time);
        var diffTime = (new Date()).getTime() - failTime.getTime();
        if (diffTime > 0) {
          var tokenString = item.device.token.toString('hex');
          r.table('users').filter(function (user) {
            return user('devices').contains(tokenString);
          }).run(conn, function (err, cursor) {
            cursor.each(function (err, user) {
              if (err || !user) {
                return;
              }
              r.table('users').get(user.id).update(function (row) {
                return {
                  devices: row('devices').filter(function (item) {
                    return item.ne(tokenString);
                  })
                };
              }).run(conn, function (err) {
                if (err) {
                  console.log('error updating user record', err);
                }
              });
            });
          });
        }
      });
  });

});

challengeAPN.on('error', function (err) {
  console.error(err.message);
});

var app = express();
app.set('trust proxy', 1);
app.use(session({
  cookie: {
    path: '/',
    httpOnly: true,
    secure: process.env.SECURE_COOKIE ? true : false,
    domain: '.' + process.env.ROOT_DOMAIN
  },
  resave: false,
  saveUninitialized: false,
  secret: process.env.SESSIONSTORE_SECRET,
  store: new RedisStore({
    host: process.env.SESSIONSTORE_PORT_6379_TCP_ADDR,
    port: process.env.SESSIONSTORE_PORT_6379_TCP_PORT
  })
}));

app.use(bodyParser.json());

// gce health check
app.get('/', function (req, res) {
  res.json({
    message: 'pong'
  });
});

// post a device token
app.post('/v1/users/me/devices', function (req, res) {

  // make sure that i am signed in
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  if (!req.body.token) {
    res.status(400);
    return res.json({
      message: 'must include a token to add for user'
    });
  }

  r.connect({
    host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
    port: process.env.USERSTORE_PORT_28015_TCP_PORT
  }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, user) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!user) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      var found = false;
      var newDevices = user.devices || [ ];
      newDevices.forEach(function (device) {
        if (device == req.body.token) {
          found = true;
        }
      });

      if (found) {
        return res.json({
          message: 'token exists'
        });
      }

      newDevices.push(req.body.token);
      r.table('users').get(req.session.userId).update({ devices: newDevices }).run(conn, function (err, result) {

        if (err || !result) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        res.status(201);
        res.json({
          message: 'device token updated'
        });

      });

    });

  });

});

// post my fitness training session
app.post('/v1/users/me/sessions', function (req, res) {

  // make sure that i am signed in
  if (!req.session || !req.session.userId) {
    console.log('not authed');
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    var userId = req.session.userId;
    var sessions = req.body;

    console.log(sessions);

    r.table('users').get(userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      // look through challenges and apply to active
      var challenges = result.challenges || [ ];
      async.forEachOf(challenges, function (challenge, index, cb) {

        // if the challenge is done then dont add the sessions to it
        if (challenge.completed || !challenge.active) {
          return cb();
        }

        // lookup the challnge
        r.table('challenges').get(challenge.id).run(conn, function (err, challengeSpec) {

          if (err) {
            return cb(err);
          }

          // use this filter over the incoming sessions
          var min_time = challengeSpec.segments[0].filter.minutes;
          var types = challengeSpec.segments[0].filter.types || [ ];

          var filteredSessions = [ ];
          req.body.forEach(function (session) {

            // check that this activity counts
            if (types.indexOf(session.activity) == -1) {
              return;
            }

            // check that it meets the time requirements
            console.log(session.interval);
            console.log(min_time);
            if (min_time && session.interval < (min_time*60)) {
              return;
            }

            session.start = new Date(session.start);
            session.end = new Date(session.end);

            // filter sessions that started before we accepted the challenge
            if (session.start.getTime() < challenge.acceptDate.getTime()) {
              return;
            }

            filteredSessions.push(session);

          });

          console.log(filteredSessions);

          // append these sessions to the user record
          Array.prototype.push.apply(challenge.sessions, filteredSessions);

          // for each session, get the start time, compute number of days from that time
          var sessions = challenge.sessions;
          var completed = false;
          var count = challengeSpec.segments[0].count;
          var days = challengeSpec.segments[0].days;
          var type = challengeSpec.segments[0].type;

          console.log('days: ', days, 'count: ', count);

          // compute whether we are completed
          sessions.forEach(function (session, i) {

            // for this first session find the rest
            var curr_count = 1;
            var startWindow = session.start;

            // all other sessions must fall within this window
            var endWindow = new Date(session.start);
            endWindow.setDate(endWindow.getDate() + days);

            console.log('window start', startWindow);
            console.log('window end', endWindow);

            sessions.forEach(function (session, j) {

              // skip own session
              if (i == j) {
                return;
              }

              // look at the remainig sessions
              if (session.start < endWindow) {
                if (type == 'sessions') {
                  curr_count = curr_count + 1;
                } else {
                  curr_count = curr_count + session.distance;
                }
              }

            });

            // check if we are done!
            if (curr_count >= count) {
              completed = true;
              return;
            }

          });

          // if goal met, mark challenge complete
          if (completed) {

            console.log('challenge completed');
            challenge.completed = true;

            // send notification to the users device indicating the challenge has been completed
            var devices = result.devices || [ ];
            devices.forEach(function (device) {
              var note = new apn.Notification();
              note.expiry = Math.floor(Date.now() / 1000) + 3600;
              note.contentAvailable = true;
              note.alert = 'Challenge "' + challengeSpec.name + '" completed!';
              note.payload = {
                type: 'challenge_completed',
                messageFrom: 'SESSIONS.IO',
                userId: result.id
              };
              var myDevice = new apn.Device(device);
              challengeAPN.pushNotification(note, myDevice);
            });

          } else {

            // send notification to the users device indicating the challenge has been completed
            var devices = result.devices || [ ];
            devices.forEach(function (device) {
              var note = new apn.Notification();
              note.expiry = Math.floor(Date.now() / 1000) + 3600;
              note.contentAvailable = true;
              note.payload = {
                type: 'new_sessions',
                messageFrom: 'SESSIONS.IO',
                userId: result.id
              };
              var myDevice = new apn.Device(device);
              challengeAPN.pushNotification(note, myDevice);
            });

          }

          cb();

        });

      }, function (err) {

        if (err) {
          console.log(err);
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        // update the user object
        r.table('users').get(req.session.userId).update(result).run(conn, function (err) {

          if (err) {
            console.log(err);
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.status(201);
          res.json({
            message: 'Sessions recorded'
          });

        });

      });

    });

  });

});

// delete the user account (trainer or client)
app.delete('/v1/users/me', function (req, res) {

  // make sure that i am signed in
  if (!req.session || !req.session.userId) {
    console.log('not authed');
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  // lookup the user in the database
  r.connect({
    host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
    port: process.env.USERSTORE_PORT_28015_TCP_PORT
  }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    // pull up the trainer to get the stripe token
    r.table('users').get(req.session.userId).run(conn, function (err, user) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!user) {
        res.status(404);
        return res.json({
          message: 'could not find trainer with the given id'
        });
      }

      var userId = req.session.userId;
      r.table('users').get(userId).delete().run(conn, function (err, deleteResult) {

        conn.close();
        if (err) { 
          res.status(500);
          return res.json({ 
            message: 'error deleting user'
          });          
        }

        req.session.destroy();
        res.json({
          message: 'user deleted successfully'
        });

      });

    });

  });

});

// native sign up
app.post('/v1/users/me', function (req, res) {

  if (req.body.password == undefined) {
    res.status(400);
    return res.json({
      message: 'must include a password to be set'
    });
  }

  r.connect({
    host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
    port: process.env.USERSTORE_PORT_28015_TCP_PORT
  }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    bcrypt.hash(req.body.password, 8, function (err, hash) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error hashing passwords'
        });
      }

      var user_record = {
        hash: hash,
        challenges: [ ],
        devices: [ ],
      };

      r.table('users').insert(user_record).run(conn, function (err, result) {

        if (err || !result.generated_keys) {
          res.status(500);
          return res.json({
            message: 'error creating new user'
          });
        }

        // set the session userId to the rethinkdb docuemnt id
        req.session.userId = result.generated_keys[0];

        // create a new user in layerkit
        res.status(201);
        res.json({
          id: req.session.userId,
          message: 'user created'
        });

      });

    });

  });

});

// native login2
app.post('/v1/native', function (req, res) {

  if (!req.body.username) {
    res.status(400);
    return res.json({
      message: 'must provide username'
    });
  }

  if (!req.body.password) {
    res.status(400);
    return res.json({
      message: 'must provide password'
    });
  }

  // now that we know everything is cool, lookup the user in rethinkdb
  r.connect({
    host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
    port: process.env.USERSTORE_PORT_28015_TCP_PORT
  }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.body.username).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      bcrypt.compare(req.body.password, result.hash, function (err, matched) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error comparing password/hash'
          });
        }

        if (!matched) {
          res.status(403);
          return res.json({
            message: 'authorization failed'
          });
        }

        req.session.userId = result.id;
        res.json({
          message: 'login successful'
        });

      });

    });

  });

});

// delete a challenge
app.delete('/v1/users/me/challenges/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // ensure the challenge exists before adding it
      r.table('challenges').get(req.params.id).run(conn, function (err, challenge) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        if (!challenge) {
          res.status(400);
          return res.json({
            message: 'challenge not found by this id'
          });
        }

        r.table('users').get(req.session.userId).update(function (row) {
          return {
            challenges: row('challenges').filter(function (item) {
              return item('id').ne(challenge.share);
            }) || [ ]
          };
        }).run(conn, function (err) {

          if (err) {
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.json({
            message: 'challenge removed'
          });

        });

      });

    });

  });

});

app.post('/v1/users/me/challenges', function (req, res) {

  // verify the incoming data
  if (!req.body || req.body.sessions != '0.1.0') {
    res.status(400);
    return res.json({
      message: 'invalid challge format'
    });
  }

  // create a challenge in the challenge table for it
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // bookmark the challenge for this user (active = false)
      r.table('challenges').insert(req.body).run(conn, function (err, reps) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'server error'
          });
        }

        // return success
        var challengeId = reps.generated_keys[0];
        console.log('generaged challengge', challengeId);

        r.table('users').get(req.session.userId).update({
          challenges: r.row('challenges').append({
            id: challengeId,
            sessions: [ ], // we will record all sessions here,
            acceptDate: new Date()
          })
        }).run(conn, function (err) {

          if (err) {
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.status(201);
          res.json({
            message: 'challenge added'
          });

        });

      });

    });

  });

});

// get the challenges that have been added for this user already
app.delete('/v1/users/me/challenges/completed/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // ensure the challenge exists before adding it
      r.table('challenges').get(req.params.id).run(conn, function (err, challenge) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        if (!challenge) {
          res.status(400);
          return res.json({
            message: 'challenge not found by this id'
          });
        }

        r.table('users').get(req.session.userId).update(function (row) {
          return {
            challenges: row('challenges').filter(function (item) {
              return item('id').ne(challenge.id);
            }) || [ ]
          };
        }).run(conn, function (err) {

          if (err) {
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.json({
            message: 'challenge removed'
          });

        });

      });

    });

  });

});

// get the challenges that have been added for this user already
app.delete('/v1/users/me/challenges/active/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // ensure the challenge exists before adding it
      r.table('challenges').get(req.params.id).run(conn, function (err, challenge) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        if (!challenge) {
          res.status(400);
          return res.json({
            message: 'challenge not found by this id'
          });
        }

        r.table('users').get(req.session.userId).update(function (row) {
          return {
            challenges: row('challenges').filter(function (item) {
              return item('id').ne(challenge.id);
            }) || [ ]
          };
        }).run(conn, function (err) {

          if (err) {
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.json({
            message: 'challenge removed'
          });

        });

      });

    });

  });

});

// get the challenges that have been added for this user already
app.delete('/v1/users/me/challenges/saved/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // ensure the challenge exists before adding it
      r.table('challenges').get(req.params.id).run(conn, function (err, challenge) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        if (!challenge) {
          res.status(400);
          return res.json({
            message: 'challenge not found by this id'
          });
        }

        r.table('users').get(req.session.userId).update(function (row) {
          return {
            challenges: row('challenges').filter(function (item) {
              return item('id').ne(challenge.id);
            }) || [ ]
          };
        }).run(conn, function (err) {

          if (err) {
            res.status(500);
            return res.json({
              message: 'error making connection to backend database'
            });
          }

          res.json({
            message: 'challenge removed'
          });

        });

      });

    });

  });

});

// deactivate this challenge (just save it again)
app.put('/v1/users/me/challenges/active/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // find the challenge
      var challenge;
      result.challenges.forEach(function (ch) {
        if (ch.id == req.params.id) {
          challenge = ch;
        }
      });

      // remove the active flag
      delete challenge.active;
      challenge.sessions = [ ];

      r.table('users').get(req.session.userId).update(function (row) {
        return {
          challenges: row('challenges').filter(function (item) {
            return item('id').ne(challenge.id);
          }).append(challenge)
        };
      }).run(conn, function (err) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        res.json({
          message: 'challenge deactivated'
        });

      });

    });

  });

});

// get the challenges that have been added for this user already
app.put('/v1/users/me/challenges/:id', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      // find the challenge
      var challenge;
      result.challenges.forEach(function (ch) {
        if (ch.id == req.params.id) {
          challenge = ch;
        }
      });

      // flag as active
      challenge.active = true;

      r.table('users').get(req.session.userId).update(function (row) {
        return {
          challenges: row('challenges').filter(function (item) {
            return item('id').ne(challenge.id);
          }).append(challenge)
        };
      }).run(conn, function (err) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'error making connection to backend database'
          });
        }

        res.json({
          message: 'challenge removed'
        });

      });

    });

  });

});

// get the completed challenges
app.get('/v1/users/me/challenges/completed', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      var challenges = result.challenges || [ ];
      var challengeResults = [ ];
      async.forEach(challenges, function (challenge, cb) {

        var id = challenge.id;

        // only include completed
        if (!challenge.completed) {
          return cb();
        }

        r.table('challenges').get(id).run(conn, function (err, chg) {

          if (err || !chg) {
            return cb();
          }

          // for each session, get the start time, compute number of days from that time
          var sessions = challenge.sessions;
          var count = chg.segments[0].count;
          var days = chg.segments[0].days;
          var type = chg.segments[0].type;

          console.log('days: ', days, 'count: ', count);

          var bestProgress = 0.0;

          // compute whether we are completed
          sessions.forEach(function (session, i) {

            // for this first session find the rest
            var curr_count = 1;
            var startWindow = session.start;

            // all other sessions must fall within this window
            var endWindow = new Date(session.start);
            endWindow.setDate(endWindow.getDate() + days);

            console.log('window start', startWindow);
            console.log('window end', endWindow);

            sessions.forEach(function (session, j) {

              // skip own session
              if (i == j) {
                return;
              }

              if (type == 'sessions') {

                // look at the remainig sessions
                if (session.start < endWindow) {
                  curr_count = curr_count + 1;
                }

              } else {

                // look at the remainig sessions
                if (session.start < endWindow) {
                  curr_count = curr_count + session.distance;
                }

              }

            });

            // check if we are done!
            progress = curr_count / count;
            if (progress > bestProgress) {
              bestProgress = progress;
            }

          });

          // record progress
          chg.progress = bestProgress;

          // add recoreded sessions
          chg.sessions = challenge.sessions;

          // we will also return progress here as well
          challengeResults.push(chg);

          cb();

        });

      }, function (err) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'server error'
          });
        }

        res.json(challengeResults);

      });

    });

  });

});

// get the challenges that have been added for this user already
app.get('/v1/users/me/challenges/active', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      var challenges = result.challenges || [ ];
      var challengeResults = [ ];
      async.forEach(challenges, function (challenge, cb) {

        var id = challenge.id;

        // dont include active or completed
        if (!challenge.active || challenge.completed) {
          return cb();
        }

        r.table('challenges').get(id).run(conn, function (err, chg) {

          if (err || !chg) {
            return cb();
          }

          // for each session, get the start time, compute number of days from that time
          var sessions = challenge.sessions;
          var count = chg.segments[0].count;
          var days = chg.segments[0].days;
          var type = chg.segments[0].type;

          console.log('days: ', days, 'count: ', count);

          var bestProgress = 0.0;

          // compute whether we are completed
          sessions.forEach(function (session, i) {

            // for this first session find the rest
            var curr_count = 1;
            var startWindow = session.start;

            // all other sessions must fall within this window
            var endWindow = new Date(session.start);
            endWindow.setDate(endWindow.getDate() + days);

            console.log('window start', startWindow);
            console.log('window end', endWindow);

            sessions.forEach(function (session, j) {

              // skip own session
              if (i == j) {
                return;
              }


              if (type == 'sessions') {

                // look at the remainig sessions
                if (session.start < endWindow) {
                  curr_count = curr_count + 1;
                }

              } else {

                // look at the remainig sessions
                if (session.start < endWindow) {
                  curr_count = curr_count + session.distance;
                }

              }

            });

            // check if we are done!
            progress = curr_count / count;
            if (progress > bestProgress) {
              bestProgress = progress;
            }

          });

          // record progress
          chg.progress = bestProgress;

          // add recoreded sessions
          chg.sessions = challenge.sessions;

          // we will also return progress here as well
          challengeResults.push(chg);

          cb();

        });

      }, function (err) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'server error'
          });
        }

        res.json(challengeResults);

      });

    });

  });

});


// get the challenges that have been added for this user already
app.get('/v1/users/me/challenges/saved', function (req, res) {

  console.log('loading saved');

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      console.log(result.challenges);

      var challenges = result.challenges || [ ];
      var challengeResults = [ ];
      async.forEach(challenges, function (challenge, cb) {

        var id = challenge.id;

        // dont include active or completed
        if (challenge.active || challenge.completed) {
          return cb();
        }

        r.table('challenges').get(id).run(conn, function (err, chg) {

          if (err || !chg) {
            return cb();
          }

          // we will also return progress here as well
          challengeResults.push(chg);

          cb();

        });

      }, function (err) {

        if (err) {
          res.status(500);
          return res.json({
            message: 'server error'
          });
        }

        console.log(challengeResults);

        res.json(challengeResults);

      });

    });

  });

});


// get the challenges that have been added for this user already
app.get('/v1/users/me/challenges', function (req, res) {

  // check if the user has a currently valid session
  if (!req.session || !req.session.userId) {
    res.status(403);
    return res.json({
      message: 'user is not authenticated'
    });
  }

  r.connect({
      host: process.env.USERSTORE_PORT_28015_TCP_ADDR,
      port: process.env.USERSTORE_PORT_28015_TCP_PORT
    }, function(err, conn) {

    if (err) {
      res.status(500);
      return res.json({
        message: 'error making connection to backend database'
      });
    }

    r.table('users').get(req.session.userId).run(conn, function (err, result) {

      if (err) {
        res.status(500);
        return res.json({
          message: 'error making connection to backend database'
        });
      }

      if (!result) {
        res.status(404);
        return res.json({
          message: 'user not found'
        });
      }

      var challenges = result.challenges || [ ];
      var challengeResults = [ ];
      async.forEach(challenges, function (challenge, cb) {

        var id = challenge.id || challenge;
        r.table('shares').get(id).run(conn, function (err, ch) {

          if (err || !ch) {
            return cb();
          }

          r.table('challenges').get(ch.challenge).run(conn, function (err, chg) {

            if (err || !chg) {
              return cb();
            }

            // overlay our own progress and results
            if (challenge.completed) {
              chg.completed = true;
            }

            // overlay the sessions that contribute
            chg.sessions = challenge.sessions;

            // compute the progress
            if (chg.completed) {
              chg.progress = 1.0;

            } else {

              // for each session, get the start time, compute number of days from that time
              var sessions = challenge.sessions;
              var count = chg.challenge[0].goal.count;
              var days = chg.challenge[0].goal.days;

              console.log('days: ', days, 'count: ', count);

              var bestProgress = 0.0;

              // compute whether we are completed
              sessions.forEach(function (session, i) {

                // for this first session find the rest
                var curr_count = 1;
                var startWindow = session.start;

                // all other sessions must fall within this window
                var endWindow = new Date(session.start);
                endWindow.setDate(endWindow.getDate() + days);

                console.log('window start', startWindow);
                console.log('window end', endWindow);

                sessions.forEach(function (session, j) {

                  // skip own session
                  if (i == j) {
                    return;
                  }

                  // look at the remainig sessions
                  if (session.start < endWindow) {
                    curr_count = curr_count + 1;
                  }

                });

                // check if we are done!
                progress = curr_count / count;
                if (progress > bestProgress) {
                  bestProgress = progress;
                }

              });

              chg.progress = bestProgress;

            }

            // we will also return progress here as well
            challengeResults.push(chg);
            cb();

          });

        });

      }, function (err) {

        res.json({
          challenges: challengeResults
        });

      });

    });

  });

});

var server = http.createServer(app);
server.listen(3000, '0.0.0.0');


function decodeJwt(token) {

    var segments = token.split('.');

    if (segments.length !== 3) {
      throw new Error('Not enough or too many segments');
    }

    // All segment should be base64
    var headerSeg = segments[0];
    var payloadSeg = segments[1];
    var signatureSeg = segments[2];

    // base64 decode and parse JSON
    var header = JSON.parse(base64urlDecode(headerSeg));
    var payload = JSON.parse(base64urlDecode(payloadSeg));

    return {
      header: header,
      payload: payload,
      signature: signatureSeg
    }
}

function base64urlDecode(str) {
  return new Buffer(base64urlUnescape(str), 'base64').toString();
};

function base64urlUnescape(str) {
  str += Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}
