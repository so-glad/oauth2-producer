'use strict';

/**
 * @author palmtale
 * @since 2017/5/22.
 */
 
 
import util from '../../main/js/utils';
util.generateRandomToken(256)
    .then(r => console.info(r))
    .catch(e => console.error(e));