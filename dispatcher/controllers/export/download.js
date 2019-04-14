'use strict';

const respond = require('../../../backend/respond');
const onError = require('../../../backend/error');
const nodeAclId = require('../../../backend/menu').nodeAclId;
const Permissions = require('core/Permissions');
const overrideEagerLoading = require('../../../backend/items').overrideEagerLoading;
const moment = require('moment');
const formListOptions = require('../../../backend/items').formListOptions;
const moduleName = require('../../../module-name');
const canonicNode = require('../../../backend/menu').canonicNode;
const locale = require('locale');

module.exports = function (req, res) {
  respond(['aclProvider', 'export', 'auth'],
    function (scope) {
      try {
        let n = canonicNode(req.params.node);
        let node = scope.metaRepo.getNode(n.code, n.ns);
        if (!node) {
          return onError(scope, new Error('Страница не найдена'), res, false);
        }
        let user = scope.auth.getUser(req);

        scope.aclProvider.checkAccess(user, nodeAclId(node), Permissions.READ)
        .then((accessible) => {
          if (!accessible) {
            throw new Error('Доступ запрещен!');
          }

          let cm = scope.metaRepo.getMeta(req.params.class ? req.params.class : node.classname, null, n.ns);
          if (!cm) {
            throw new Error('Не удалось определить класс');
          }

          let exporter = scope.export.exporter(req.params.format, {class: cm, item: req.params.id});
          if (!exporter) {
            throw new Error('Не удалось определить экспортер');
          }
          return scope.export.result(
            req.params.format,
            {className: cm.getCanonicalName(), uid: user.id(), item: req.params.id, stream: true}
          );
        }).then((result) => {
          if (result && result.stream) {
            result.options((err, opts) => {
              if (err) {
                return onError(scope, err, res, true);
              }
              result.stream((err, stream) => {
                res.status(200);
                res.set('Content-Disposition',
                  'attachment; filename="' + encodeURIComponent(result.name) +
                  '";filename*=UTF-8\'\'' + encodeURIComponent(result.name));
                res.set('Content-Type', opts.mimetype || 'application/octet-stream');
                if (opts.size) {
                  res.set('Content-Length', opts.size);
                }
                if (opts.encoding) {
                  res.set('Content-Encoding', opts.encoding);
                }
                stream.pipe(res);
              });
            });
          } else {
            throw new Error('File not found!');
          }
        }).catch((err) => {
          onError(scope, err, res, true);
        });
      } catch (err) {
        onError(scope, err, res, true);
      }
    },
    res
  );
}