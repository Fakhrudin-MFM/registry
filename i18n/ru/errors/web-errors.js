/**
 * Created by Vasiliy Ermilov (ermilov.work@yandex.ru).
 */
'use strict';

const codes = require('../../../errors/web-errors');

module.exports = {
  [codes.ITEM_EXISTS]: `Failed to save object. There is another %class with the same %attr attribute value. Use the search or contact the administrator.`,
  [codes.ITEM_EXISTS_MULTI]: `Failed to save object. There is another %class with specified attribute values. Use the search or contact the administrator.`
};
