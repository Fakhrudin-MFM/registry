'use strict';
/**
 * Created by krasilneg on 25.05.18.
 */
const HtmlEntities = require('html-entities').AllHtmlEntities;
const html_entities = new HtmlEntities();
const viewPathResolver = require('lib/util/viewResolver');
const Item = require('core/interfaces/DataRepository').Item;


module.exports = function (app) {
  app.locals.htmlEntities = function (str) {
    return html_entities.encode(str);
  };

  app.locals.cssFromTags = function (field) {
    let result = [];
    if (field.options && typeof field.options === 'object') {
      if (Array.isArray(field.options.cssClasses)) {
        result.push(...field.options.cssClasses);
      }
    }
    if (Array.isArray(field.tags)) {
      for (let i = 0; i < field.tags.length; i++) {
        if (field.tags[i].substr(0, 4) === 'css-class:') {
          result.push(field.tags[i].substr(4));
        }
      }
    }
    return result.join(' ');
  };

  app.locals.styleFromTags = function (field) {
    let result = [];
    if (field.options && typeof field.options === 'object') {
      if (field.options.cssStyles && typeof field.options.cssStyles === 'object') {
        for (let style in field.options.cssStyles) {
          if (field.options.cssStyles.hasOwnProperty(style)) {
            result.push(style + ':' + field.options.cssStyles[style]);
          }
        }
      }
    }
    if (Array.isArray(field.tags)) {
      for (let i = 0; i < field.tags.length; i++) {
        if (field.tags[i].substr(0, 4) === 'css:') {
          result.push(field.tags[i].substr(4));
        }
      }
    }
    return result.join(';');
  };

  app.locals.customTpl = function (field) {
    if (field.options && typeof field.options === 'object') {
      if (field.options.template) {
        return field.options.template;
      }
    }
    return null;
  };

  app.locals.resolveTpl = viewPathResolver(app);

  app.locals.getAttrPermissions = function (item, attr) {
    let cntxt = item;
    if (attr && attr.indexOf('.') > 0) {
      let path = attr.split('.');
      for (let i = 0; i < path.length - 1; i++) {
        if (!(cntxt instanceof Item)) {
          return false;
        }
        let p = cntxt.property(path[i]);
        if (!p) {
          return false;
        }
        cntxt = p.evaluate();
        attr = path[i + 1];
      }
    }
    return (cntxt && attr && cntxt.attrPermissions && cntxt.attrPermissions[attr]) || false;
  };

  app.locals.getFieldCommands = function (field) {
    return Array.isArray(field.commands) ? field.commands : (
      (field.type === 2) ?
        [
          {
            id: 'SELECT',
            caption: 'Select'
          },
          {
            id: 'CREATE',
            caption: 'Create'
          },
          {
            id: 'EDIT',
            caption: 'Edit',
            needSelectedItem: true
          },
          {
            id: 'REMOVE',
            caption: 'Remove',
            needSelectedItem: true
          }
        ] :
        [
          {
            id: 'ADD',
            caption: 'Add'
          },
          {
            id: 'CREATE',
            caption: 'Create'
          },
          {
            id: 'EDIT',
            caption: 'Edit',
            needSelectedItem: true
          },
          {
            id: 'REMOVE',
            caption: 'Remove',
            isBulk: true
          },
          {
            id: 'DELETE',
            caption: 'Delete',
            isBulk: true
          }
        ]
    );
  };
};